# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# Copyright © 2024 ReinforcedAI

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.


import os
import pickle
import time
from typing import List

import bittensor as bt
from dotenv import load_dotenv


from ai_audits.protocol import AuditsSynapse, VulnerabilityReport, ReferenceReport
from ai_audits.contract_provider import FileContractProvider
from neurons.base import ReinforcedValidatorNeuron, get_random_uids


CONTRACT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "contract_templates"
)
PROVIDER = FileContractProvider(CONTRACT_DIR)
CYCLE_TIME = 3600


class Validator(ReinforcedValidatorNeuron):
    WEIGHT_TIME = 0.1
    WEIGHT_SCORE = 0.9

    def __init__(self, config=None):
        self._step = 0
        self._start_time = time.time()
        super().__init__(config=config)
        bt.logging.info("load_state()")
        self.load_state()
        self.set_identity()

    async def forward(self):
        """
        Validator forward pass. Consists of:
        - Generating the query
        - Querying the miners
        - Getting the responses
        - Rewarding the miners
        - Updating the scores
        """
        miner_uids = self.metagraph.n.item()
        bt.logging.info(f"Metagraph uids: {miner_uids}")
        active_uids = [
            index
            for index, is_active in enumerate(self.metagraph.active)
            if is_active == 1
        ]
        bt.logging.info(f"Active UIDs: {active_uids}")
        axon_count = len(self.metagraph.axons) - 1

        miner_selection_size = min(axon_count, self.config.neuron.sample_size)
        miner_uids = get_random_uids(self, k=miner_selection_size, exclude=[self.uid])

        bt.logging.info(f"Selected UIDs: {miner_uids}")
        bt.logging.info(f"Self UID: {self.uid}")

        pair = PROVIDER.get_random_pair()
        bt.logging.info(f"task: {pair}")

        synapse = AuditsSynapse(contract_code=pair.contract)
        bt.logging.info(f"Axons: {self.metagraph.axons}")

        if os.getenv("RUN_LOCAL", "0") != "1":
            self.dendrite.external_ip = "127.0.0.1"

        responses = self.dendrite.query(
            axons=[self.metagraph.axons[uid] for uid in miner_uids],
            synapse=synapse,
            deserialize=False,
            timeout=600,
        )
        bt.logging.info(f"Received responses: {responses}")

        rewards = self.validate_responses(responses, pair.reference_report)

        bt.logging.info(f"Scored responses: {rewards}")

        self.update_scores(rewards, miner_uids)

    def validate_responses(
        self,
        responses: List[AuditsSynapse],
        reference_report: List[ReferenceReport] = None,
    ) -> List[float]:
        if reference_report is None:
            reference_report = []
        axon_info = self.axon.info()
        times = [
            x.dendrite.process_time
            for x in responses
            if x.dendrite.process_time is not None and x.axon.hotkey != axon_info.hotkey
        ]
        bt.logging.debug(f"axons response times: {times}")

        min_time = min(times) if times else 0.0

        bt.logging.debug(f"minimal response time: {min_time}")

        scores: list[float] = []

        for synapse in responses:
            bt.logging.debug(
                f"synapse: axon hotkey: {synapse.axon.hotkey} | is success: {synapse.is_success} |  is blacklisted: {synapse.is_blacklist} | message: {synapse.axon.status_message}"
            )
            scores_by_report = (
                self.validate_reports_by_reference(synapse.response, reference_report)
                * self.WEIGHT_SCORE
            )
            scores_by_time = (
                (
                    (min_time / synapse.dendrite.process_time)
                    if synapse.dendrite.process_time
                    and synapse.axon.hotkey != axon_info.hotkey
                    else 0
                )
                * (scores_by_report / self.WEIGHT_SCORE)
                * self.WEIGHT_TIME
            )
            scores.append(scores_by_report + scores_by_time)
        return scores

    @classmethod
    def validate_reports_by_reference(
        cls,
        report: List[VulnerabilityReport] | None,
        reference_report: List[ReferenceReport],
    ) -> float:
        if report is None or not reference_report:
            return 0.0

        reference_count = len(reference_report)
        max_vuln = {}

        for ref in reference_report:
            for vuln in ref.vulnerability_class:
                max_vuln[vuln] = max_vuln.get(vuln, 0) + 1
        report_vuln = {}

        for rep in report:
            vuln_class = rep.vulnerability_class.lower()
            if vuln_class not in max_vuln:
                # Unknown vulnerability for template, unscored
                continue
            report_vuln[vuln_class] = report_vuln.get(vuln_class, 0) + 1
            if report_vuln[vuln_class] > max_vuln[vuln_class]:
                # Found extra vulnerability, unknown by template, unscored
                report_vuln[vuln_class] = max_vuln[vuln_class]

        report_count = sum(report_vuln.values())

        # # The number of detected vulnerabilities must match the template. Otherwise, reduce scores
        # if report_count > reference_count:
        #     report_count = reference_count - abs(report_count - reference_count)
        # if report_count < 0:
        #     report_count = 0

        # Currently, we forgive the miner for identifying additional vulnerabilities
        # due to the imperfection of the templates
        if report_count > reference_count:
            report_count = reference_count
        return report_count / reference_count

    # TODO: This function is currently unused, but may be useful in the future.
    #  Consider re-evaluating its necessity before removing.
    @classmethod
    def validate_report(
        cls, report: VulnerabilityReport, reference_report: ReferenceReport
    ) -> float:
        if report.vulnerability_class.lower() in reference_report.vulnerability_class:
            return 1.0
        else:
            return 0.0

    def save_state(self):
        """Saves the state of the validator to a file."""
        bt.logging.info("Saving validator state.")

        # Save the state of the validator to file.
        state = {
            "step": self.step,
            "scores": self.scores,
            "hotkeys": self.hotkeys,
        }

        with open(self.config.neuron.full_path + "/state.pkl", "wb") as f:
            pickle.dump(state, f)

    def load_state(self):
        """Loads the state of the validator from a file."""
        bt.logging.info("Loading validator state.")

        with open(self.config.neuron.full_path + "/state.pkl", "rb") as f:
            state = pickle.load(f)

        self.step = state["step"]
        self.scores = state["scores"]
        self.hotkeys = state["hotkeys"]

    @property
    def step(self):
        return self._step

    @step.setter
    def step(self, value):
        if value > 0:
            if os.getenv("VALIDATOR_TIME", None):
                validator_time = int(os.getenv("VALIDATOR_TIME"))
                current_minute = int(time.strftime("%M"))
                if not 0 <= validator_time <= 59:
                    raise ValueError("VALIDATOR_TIME has incorrect value!")

                if current_minute == validator_time:
                    wait_time = 3600
                else:
                    wait_time = (validator_time - current_minute) % 60
                time.sleep(wait_time * 60)
            else:
                elapsed_time = time.time() - self._start_time
                if elapsed_time < CYCLE_TIME:
                    time.sleep(CYCLE_TIME - elapsed_time)
                self._start_time = time.time()

        self._step = value


if __name__ == "__main__":
    load_dotenv()
    with Validator() as validator:
        while True:
            bt.logging.info(f"Validator running... {time.time()}")
            time.sleep(1200)
