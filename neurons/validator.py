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


import time
from typing import List

# Bittensor
import bittensor as bt
import torch

# import base validator class which takes care of most of the boilerplate
from template.base.validator import BaseValidatorNeuron

# Bittensor Validator Template:
from template.validator import forward
from unique_subnet.protocol import UniqueSynapse


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
        bt.logging.info(f"Miner uids: {miner_uids}")

        synapse = UniqueSynapse(nums1=2 , nums2=3)
        bt.logging.info(f"Axons: {self.metagraph.axons}")

        responses = self.dendrite.query(
            axons=[self.metagraph.axons[1]],
            synapse=synapse,
            deserialize=False,
        )

        bt.logging.info(f"Received responses: {responses}")

        rewards = self.get_rewards(responses)

        bt.logging.info(f"Scored responses: {rewards}")

        self.update_scores(rewards, [1])
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

   

    def reward(self, response: UniqueSynapse) -> float:
        predictions = response.response
        if predictions is None:
            return 0.0
        return  self.get_number_reward(response.nums1 + response.nums2, predictions)
        
       

    def get_rewards(
        self,
        responses: List[UniqueSynapse],
    ) -> torch.FloatTensor:
        arr = [self.reward(response) for response in responses]
        bt.logging.info(f"rewards: {arr}")
        result = torch.FloatTensor(
           arr 
        )
        bt.logging.info(f"rewards: {result}")
        return result


# The main function parses the configuration and runs the validator.
if __name__ == "__main__":
    with Validator() as validator:
        while True:
            bt.logging.info(f"Validator running... {time.time()}")
            time.sleep(5)
