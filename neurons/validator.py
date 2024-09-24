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
from typing import List

# Bittensor
import bittensor as bt
import requests

# import base validator class which takes care of most of the boilerplate
from template.base.validator import BaseValidatorNeuron

# Bittensor Validator Template:
from template.utils.uids import get_random_uids
from template.validator import forward
from ai_audits.protocol import AuditsSynapse
from dotenv import load_dotenv


contract_code: str = """
contract Wallet {
    mapping (address => uint) userBalance;
   
    function getBalance(address u) constant returns(uint){
        return userBalance[u];
    }

    function addToBalance() payable{
        userBalance[msg.sender] += msg.value;
    }   

    function withdrawBalance(){
        // send userBalance[msg.sender] ethers to msg.sender
        // if mgs.sender is a contract, it will call its fallback function
        if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){
            throw;
        }
        userBalance[msg.sender] = 0;
    }   
}
"""


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
        random_number = random.randint(0, 1000)
        mutated_contract_code = contract_code.replace(
            "contract Wallet", f"contract Wallet_{random_number}"
        )
        synapse = AuditsSynapse(contract_code=mutated_contract_code)
        bt.logging.info(f"Axons: {self.metagraph.axons}")

        responses = self.dendrite.query(
            axons=[self.metagraph.axons[uid] for uid in miner_uids],
            synapse=synapse,
            deserialize=False,
            timeout=600,
        )
        bt.logging.info(f"Received responses: {responses}")

        for miner_uid, response in zip(miner_uids, responses):
            requests.post(
                f"{os.getenv('VALIDATOR_SERVER')}/validate?uid={miner_uid}",
                json={"result": response.response},
            )

            if not (
                requests.get(
                    f"{os.getenv('VALIDATOR_SERVER')}/get_validation_for_miner?uid={miner_uid}"
                )
            ):
                raise ValueError("Response from miner is not int")

        rewards = self.get_rewards(responses)

        bt.logging.info(f"Scored responses: {rewards}")

        self.update_scores(rewards, miner_uids)
        # TODO(developer): Rewrite this function based on your protocol definition.
        # return await forward(self)

    def get_number_reward(self, true_number: int, predicted_number: int) -> float:
        """
        Calculate the reward based on the proximity of the predicted number to the true number.

        Args:
        - true_number (int): The true number.
        - predicted_number (int): The predicted number.

        Returns:
        - float: The reward value, normalized to be between 0 and 1.
        """
        max_difference = 10

        difference = abs(true_number - predicted_number)

        if difference == 0:
            return 1.0
        elif difference <= max_difference:
            res = 1.0 - (difference / max_difference)
            return 0.5
        else:
            return 0.0

    def reward(self, response: AuditsSynapse) -> float:
        predictions = response.response
        if predictions is None:
            return 0.0
        return self.get_number_reward(response.num1 + response.num2, predictions)

    def get_rewards(
        self,
        responses: List[AuditsSynapse],
    ) -> list[float]:
        return [self.reward(response) for response in responses]


# The main function parses the configuration and runs the validator.
if __name__ == "__main__":
    load_dotenv()
    with Validator() as validator:
        while True:
            bt.logging.info(f"Validator running... {time.time()}")
            time.sleep(5)
