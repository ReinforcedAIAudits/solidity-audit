# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# TODO(developer): Set your name
# Copyright © 2023 <your name>

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
import random
import time
from typing import Counter, List

# Bittensor
import bittensor as bt
from fastapi.encoders import jsonable_encoder

# import base validator class which takes care of most of the boilerplate
from blackbox_example.subnet_utils import create_session
from template.base.validator import BaseValidatorNeuron

# Bittensor Validator Template:
from template.utils.uids import get_random_uids
from ai_audits.protocol import AuditsSynapse, VulnerabilityReport
from ai_audits.contract_provider import TemplatePair
from dotenv import load_dotenv
import numpy as np


class Validator(BaseValidatorNeuron):
    """
    Your validator neuron class. You should use this class to define your validator's behavior. In particular, you should replace the forward function with your own logic.

    This class inherits from the BaseValidatorNeuron class, which in turn inherits from BaseNeuron. The BaseNeuron class takes care of routine tasks such as setting up wallet, subtensor, metagraph, logging directory, parsing config, etc. You can override any of the methods in BaseNeuron if you need to customize the behavior.

    This class provides reasonable default behavior for a validator such as keeping a moving average of the scores of the miners and using them to set weights at the end of each epoch. Additionally, the scores are reset for new hotkeys at the end of each epoch.
    """

    def __init__(self, config=None):
        super(Validator, self).__init__(config=config)
        bt.logging.info("load_state()")
        self.load_state()

        # TODO(developer): Anything specific to your use case you can do here

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
        task_from_service = (
            create_session()
            .get(f"{os.getenv('VALIDATOR_SERVER')}/generate_contract")
            .json()
        )
        print(f"{task_from_service}")
        pair = TemplatePair(**task_from_service)

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
        reference_report: List[VulnerabilityReport] = [],
    ) -> List[float]:
        return [
            self.validate_reports_by_reference(synapse.response, reference_report)
            for synapse in responses
        ]

    def validate_reports_by_reference(
        self,
        report: List[VulnerabilityReport] | None,
        reference_report: List[VulnerabilityReport],
    ) -> float:
        if report is None or not reference_report:
            return 0.0

        finded_vulns = [vuln.vulnerability_class for vuln in report]
        reference_vulns = [vuln.vulnerability_class for vuln in reference_report]
        finded_count = Counter(finded_vulns)
        reference_count = Counter(reference_vulns)

        intersection = [
            vuln
            for vuln in finded_vulns
            for _ in range(min(finded_count[vuln], reference_count[vuln]))
        ]

        return len(intersection) / len(reference_vulns)

    # TODO: This function is currently unused, but may be useful in the future. Consider re-evaluating its necessity before removing.
    def validate_report(
        self, report: VulnerabilityReport, reference_report: VulnerabilityReport
    ) -> float:
        if report.vulnerability_class == reference_report.vulnerability_class:
            return 1.0
        else:
            return 0.0


# The main function parses the configuration and runs the validator.
if __name__ == "__main__":
    load_dotenv()
    with Validator() as validator:
        while True:
            bt.logging.info(f"Validator running... {time.time()}")
            time.sleep(5)
