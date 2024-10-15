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
import time
from typing import List

# Bittensor
import bittensor as bt

from template.base.validator import BaseValidatorNeuron

# Bittensor Validator Template:
from template.utils.uids import get_random_uids
from ai_audits.protocol import AuditsSynapse, VulnerabilityReport
from ai_audits.contract_provider import FileContractProvdier
from dotenv import load_dotenv


CONTRACT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "contract_templates"
)
PROVIDER = FileContractProvdier(CONTRACT_DIR)


class Validator(BaseValidatorNeuron):
    def __init__(self, config=None):
        super(Validator, self).__init__(config=config)
        bt.logging.info("load_state()")
        self.load_state()

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

        responses = self.dendrite.query(
            axons=[self.metagraph.axons[uid] for uid in miner_uids],
            synapse=synapse,
            deserialize=False,
            timeout=600,
        )
        bt.logging.info(f"Received responses: {responses}")

        rewards = self.validate_responses(responses, pair.vulnerability_report)

        bt.logging.info(f"Scored responses: {rewards}")

        self.update_scores(rewards, miner_uids)

    def validate_responses(
        self,
        responses: List[AuditsSynapse],
        reference_report: List[VulnerabilityReport] = None,
    ) -> List[float]:
        if reference_report is None:
            reference_report = []
        times = [x.dendrite.process_time for x in responses]
        min_time = min(times)
        return [
            (self.validate_reports_by_reference(synapse.response, reference_report)) * 0.9 +
            (min_time / synapse.dendrite.process_time) * 0.1
            for synapse in responses
        ]

    @classmethod
    def validate_reports_by_reference(
        cls, report: List[VulnerabilityReport] | None, reference_report: List[VulnerabilityReport]
    ) -> float:
        if report is None or not reference_report:
            return 0.0

        found_vulnerabilities = [vuln.vulnerability_class for vuln in report]
        reference_vulnerabilities = [vuln.vulnerability_class for vuln in reference_report]
        diff = {
            x: abs(reference_vulnerabilities.count(x) - found_vulnerabilities.count(x))
            for x in set(reference_vulnerabilities)
        }
        return 1 - (sum(diff.values()) / len(reference_vulnerabilities))

    # TODO: This function is currently unused, but may be useful in the future.
    #  Consider re-evaluating its necessity before removing.
    @classmethod
    def validate_report(
        cls, report: VulnerabilityReport, reference_report: VulnerabilityReport
    ) -> float:
        if report.vulnerability_class == reference_report.vulnerability_class:
            return 1.0
        else:
            return 0.0


if __name__ == "__main__":
    load_dotenv()
    with Validator() as validator:
        while True:
            bt.logging.info(f"Validator running... {time.time()}")
            time.sleep(5)
