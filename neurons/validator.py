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


import asyncio
import os
import pickle
import time
from typing import List

import bittensor as bt
from dotenv import load_dotenv


from ai_audits.protocol import AuditsSynapse, VulnerabilityReport, ValidatorTask
from ai_audits.subnet_utils import create_session, is_synonyms
from neurons.base import ReinforcedValidatorNeuron, get_random_uids, ScoresBuffer

load_dotenv()
CYCLE_TIME = int(os.getenv("VALIDATOR_SEND_REQUESTS_EVERY_X_SECS", "3600"))


class Validator(ReinforcedValidatorNeuron):
    WEIGHT_TIME = 0.1
    WEIGHT_SCORE = 0.9
    MAX_BUFFER = int(os.getenv("VALIDATOR_BUFFER", "100"))

    def __init__(self, config=None):
        self._step = 0
        self._start_time = time.time()
        self._validator_time_min = (
            int(os.getenv("VALIDATOR_TIME"))
            if os.getenv("VALIDATOR_TIME")
            and 0 <= int(os.getenv("VALIDATOR_TIME")) <= 59
            else None
        )

        self._buffer_scores = ScoresBuffer(self.MAX_BUFFER)
        super().__init__(config=config)
        self.set_identity()

    @classmethod
    def get_audit_task(cls, vulnerability_type: str | None = None) -> ValidatorTask:
        result = create_session().post(
            f"{os.getenv('MODEL_SERVER')}/task",
            *([] if vulnerability_type is None else [vulnerability_type]),
            headers={"Content-Type": "text/plain"},
        )

        if result.status_code != 200:
            bt.logging.info(f"Not successful AI response. Description: {result.text}")
            raise ValueError("Unable to receive task from MODEL_SERVER!")

        json = result.json()
        bt.logging.info(f"Response from model server: {json}")
        task = ValidatorTask(**json)
        return task

    def sync(self):
        self.load_state()
        return super().sync()

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

        max_retries_to_get_tasks = 10
        retry_delay = 10

        for attempt in range(max_retries_to_get_tasks):
            try:
                task = self.get_audit_task()
                bt.logging.info(f"task: {task}")
                break
            except ValueError as e:
                bt.logging.warning(
                    f"Attempt {attempt + 1}/{max_retries_to_get_tasks} failed: {str(e)}"
                )
                if attempt < max_retries_to_get_tasks - 1:
                    bt.logging.info(
                        f"Waiting {retry_delay} seconds before next attempt..."
                    )
                    await asyncio.sleep(retry_delay)
                else:
                    bt.logging.error("Max retries reached. Unable to get audit task.")
                    return

        if os.getenv("RUN_LOCAL", "").lower() != "true":
            self.dendrite.external_ip = "127.0.0.1"

        synapse = AuditsSynapse(contract_code=task.contract_code)
        bt.logging.info(f"Axons: {self.metagraph.axons}")

        responses = self.dendrite.query(
            axons=[self.metagraph.axons[uid] for uid in miner_uids],
            synapse=synapse,
            deserialize=False,
            timeout=600,
        )
        bt.logging.info(f"Received responses: {responses}")

        rewards = self.validate_responses(responses, task)

        bt.logging.info(f"Scored responses: {rewards}")

        for num, uid in enumerate(miner_uids):
            self._buffer_scores.add_score(uid, rewards[num])

        self.update_scores(rewards, miner_uids)

    def set_weights(self):
        result, msg = self.subtensor.set_weights(
            wallet=self.wallet,
            netuid=self.config.netuid,
            uids=self._buffer_scores.uids(),
            weights=self._buffer_scores.scores(),
            wait_for_finalization=False,
            wait_for_inclusion=False,
            version_key=self.spec_version,
        )
        if result is True:
            bt.logging.info("set_weights on chain successfully!")
        else:
            bt.logging.error("set_weights failed", msg)

    def validate_responses(
        self,
        responses: List[AuditsSynapse],
        task: ValidatorTask = None,
    ) -> List[float]:
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
                f"synapse: axon hotkey: {synapse.axon.hotkey} | is success: {synapse.is_success} | "
                f"is blacklisted: {synapse.is_blacklist} | message: {synapse.axon.status_message}"
            )
            scores_by_report = (
                self.validate_reports_by_reference(synapse.response, task)
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
        task: ValidatorTask,
    ) -> float:
        if report is None or not task:
            return 0.0

        vulnerabilities_found = [x.vulnerability_class for x in report]
        score = (
            1.0
            if any(
                is_synonyms(task.vulnerability_class, vuln)
                for vuln in vulnerabilities_found
            )
            else 0.0
        )
        # # The number of detected vulnerabilities must match the template. Otherwise, reduce scores
        # if len(vulnerabilities_found) > 1:
        #     score = score / len(vulnerabilities_found)

        # Currently, we forgive the miner for identifying additional vulnerabilities
        # due to the imperfection of LLM generation

        return score

    # TODO: This function is currently unused, but may be useful in the future.
    #  Consider re-evaluating its necessity before removing.
    @classmethod
    def validate_report(cls, report: VulnerabilityReport, task: ValidatorTask) -> float:
        if is_synonyms(task.vulnerability_class, report.vulnerability_class):
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
            "buffer_scores": self._buffer_scores.dump(),
            "hotkeys": self.hotkeys,
        }

        with open(self.config.neuron.full_path + "/state.pkl", "wb") as f:
            pickle.dump(state, f)

    def load_state(self):
        """Loads the state of the validator from a file."""
        bt.logging.info("Loading validator state.")
        try:
            with open(self.config.neuron.full_path + "/state.pkl", "rb") as f:
                state = pickle.load(f)

            self.step = state["step"]
            self.scores = state["scores"]
            buf = ScoresBuffer(self.MAX_BUFFER)
            buf.load(state.get("buffer_scores", {}))
            self._buffer_scores = buf
            self.hotkeys = state["hotkeys"]
        except FileNotFoundError:
            bt.logging.error("State file is not found.")
            self.save_state()

    @property
    def step(self):
        return self._step

    @step.setter
    def step(self, value):
        if value > 0:
            if self._validator_time_min:
                current_minute = int(time.strftime("%M"))
                if current_minute == self._validator_time_min:
                    wait_time_min = 60
                else:
                    wait_time_min = (self._validator_time_min - current_minute) % 60
                time.sleep(wait_time_min * 60)
            else:
                elapsed_time = time.time() - self._start_time
                if elapsed_time < CYCLE_TIME:
                    time.sleep(CYCLE_TIME - elapsed_time)
                self._start_time = time.time()

        self._step = value


if __name__ == "__main__":
    with Validator() as validator:
        while True:
            bt.logging.info(f"Validator running... {time.time()}")
            time.sleep(1200)
