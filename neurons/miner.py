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
import traceback
import typing
import bittensor as bt
from bittensor.utils.btlogging import logging
from dotenv import load_dotenv

from ai_audits.nft_protocol import ReportMessage
from ai_audits.subnet_utils import create_session
from neurons.base import ReinforcedMinerNeuron
from ai_audits.protocol import AuditsSynapse, TaskMessage, VulnerabilityReport


class Miner(ReinforcedMinerNeuron):
    REQUEST_PERIOD = int(os.getenv("MINER_ACCEPT_REQUESTS_EVERY_X_SECS", 20 * 60))
    _last_call_from_dendrite: dict[str, float]
    _dendrite_whitelist: list[str]

    # TODO registration
    def __init__(self, config=None):
        super(Miner, self).__init__(config=config)
        self._last_call_from_dendrite = {}
        self._dendrite_whitelist = [
            key.strip() for key in os.getenv("DENDRITE_WHITELIST", "").split(",") if key.strip()
        ]
        self.load_website_keys()
        self.set_identity()

    def load_website_keys(self):
        try:
            keys_response = create_session().get(os.getenv("KEYS_WEBSITE", "https://audit.reinforced.app/keys"))
            if keys_response.status_code == 200:
                keys_list = keys_response.json()
                if isinstance(keys_list, list) and all(isinstance(key, str) for key in keys_list):
                    self._dendrite_whitelist = list(set(self._dendrite_whitelist) | set(keys_list))
                else:
                    logging.error(f"key list has invalid format: {keys_list}")
            else:
                logging.info(f"Something went wrong with the key service. Status code: {keys_response.status_code}")
        except Exception as e:
            logging.error(f"An error occurred while connection to key service: {e}")

    @classmethod
    def do_audit_code(cls, contract_code: str) -> list[VulnerabilityReport]:
        result = create_session().post(
            f"{os.getenv('MODEL_SERVER')}/submit",
            contract_code,
            headers={"Content-Type": "text/plain"},
        )
        # TODO: Remove the error and allow sending a synapse with an empty response + log this event
        if result.status_code != 200:
            logging.info(f"Not successful AI response. Description: {result.text}")
            raise ValueError("Contract audit is not successful!")

        json = result.json()
        logging.info(f"Response from model server: {json}")
        vulnerabilities = [
            VulnerabilityReport(
                **vuln,
            )
            for vuln in json
        ]
        return vulnerabilities

    async def forward(self, task: TaskMessage) -> typing.List[VulnerabilityReport]:
        """
        Processes the incoming task by performing a predefined operation on the input data.
        """
        logging.info(f"Received task from validator {task}")

        return self.do_audit_code(task.code)

    async def blacklist(self, request: TaskMessage) -> typing.Tuple[bool, str]:
        """
        Determines whether an incoming request should be blacklisted and thus ignored.
        """
        # if synapse.dendrite is None or synapse.dendrite.hotkey is None:
        #     logging.warning("Received a request without a dendrite or hotkey.")
        #     return True, "Missing dendrite or hotkey"

        if request.validator_ss58_hotkey is None:
            logging.warning("Received a request without a dendrite or hotkey.")
            return True, "Missing dendrite or hotkey"

        if request.validator_ss58_hotkey in self._dendrite_whitelist:
            return False, f"Hotkey {request.validator_ss58_hotkey} is whitelisted"
        # TODO(developer): Define how miners should blacklist requests.
        uid = self.metagraph.hotkeys.index(request.validator_ss58_hotkey)

        if (
            not self.config.blacklist.allow_non_registered
            and request.validator_ss58_hotkey not in self.metagraph.hotkeys
        ):
            # Ignore requests from un-registered entities.
            logging.trace(f"Blacklisting un-registered hotkey {request.validator_ss58_hotkey}")
            return True, "Unrecognized hotkey"

        current_time = time.time()

        if request.validator_ss58_hotkey in self._last_call_from_dendrite:
            time_since_last_request = current_time - self._last_call_from_dendrite[request.validator_ss58_hotkey]

            if time_since_last_request < self.REQUEST_PERIOD:
                return (
                    True,
                    f"Request submitted too soon. {int(self.REQUEST_PERIOD - time_since_last_request)} "
                    f"second(s) left until the next request is allowed. "
                    f"Dendrite's associated hotkey: {request.validator_ss58_hotkey}",
                )

        self._last_call_from_dendrite[request.validator_ss58_hotkey] = current_time

        if self.config.blacklist.force_validator_permit:
            # If the config is set to force validator permit, then we should only allow requests from validators.
            if not self.metagraph.validator_permit[uid]:
                logging.warning(f"Blacklisting a request from non-validator hotkey {request.validator_ss58_hotkey}")
                return True, "Non-validator hotkey"

        logging.trace(f"Not Blacklisting recognized hotkey {request.validator_ss58_hotkey}")
        return False, "Hotkey recognized!"

    async def priority(self, synapse: AuditsSynapse) -> float:
        """
        The priority function determines the order in which requests are handled. More valuable or higher-priority
        requests are processed before others.
        """
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            logging.warning("Received a request without a dendrite or hotkey.")
            return 0.0

        if synapse.dendrite.hotkey in self._dendrite_whitelist:
            return self.metagraph.S.max() + 1.0

        # TODO(developer): Define how miners should prioritize requests.
        caller_uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)  # Get the caller index.
        priority = float(self.metagraph.S[caller_uid])  # Return the stake as the priority.
        logging.trace(f"Prioritizing {synapse.dendrite.hotkey} with value: {priority}")
        return priority

    def run(self):
        """
        Initiates and manages the main loop for the miner on the Bittensor network. The main loop handles graceful shutdown on keyboard interrupts and logs unforeseen errors.

        This function performs the following primary tasks:
        1. Check for registration on the Bittensor network.
        2. Starts the miner's axon, making it active on the network.
        3. Periodically resynchronizes with the chain; updating the metagraph with the latest network state and setting weights.

        The miner continues its operations until `should_exit` is set to True or an external interruption occurs.
        During each epoch of its operation, the miner waits for new blocks on the Bittensor network, updates its
        knowledge of the network (metagraph), and sets its weights. This process ensures the miner remains active
        and up-to-date with the network's latest state.

        Note:
            - The function leverages the global configurations set during the initialization of the miner.
            - The miner's axon serves as its interface to the Bittensor network, handling incoming and outgoing requests.

        Raises:
            KeyboardInterrupt: If the miner is stopped by a manual interruption.
            Exception: For unforeseen errors during the miner's operation, which are logged for diagnosis.
        """

        # Check that miner is registered on the network.
        self.sync()

        # Serve passes the axon information to the network + netuid we are hosting on.
        # This will auto-update if the axon port of external ip have changed.
        bt.logging.info(
            f"Serving miner axon {self.axon} on network: {self.config.subtensor.chain_endpoint} with netuid: {self.config.netuid}"
        )
        self.axon.serve(netuid=self.config.netuid, subtensor=self.subtensor)  # Axon sends information to the network.

        # Start  starts the miner's axon, making it active on the network.
        self.axon.start()

        bt.logging.info(f"Miner starting at block: {self.block}")

        # This loop maintains the miner's operations until intentionally stopped.
        try:
            while not self.should_exit:
                while self.block - self.metagraph.last_update[self.uid] < self.config.neuron.epoch_length:
                    # Wait before checking again.
                    time.sleep(1)

                    # Check if we should exit.
                    if self.should_exit:
                        break

                # Sync metagraph and potentially set weights.
                self.sync()
                self.step += 1

        # If someone intentionally stops the miner, it'll safely terminate operations.
        except KeyboardInterrupt:
            self.axon.stop()
            bt.logging.success("Miner killed by keyboard interrupt.")
            exit()

        # In case of unforeseen errors, the miner will log the error and continue operations.
        except Exception as e:
            bt.logging.error(traceback.format_exc())

    def save_state(self):
        pass


# This is the main function, which runs the miner.
if __name__ == "__main__":
    load_dotenv()
    with Miner() as miner:
        while True:
            logging.info(f"Miner running... {time.time()}")
            time.sleep(1200)
