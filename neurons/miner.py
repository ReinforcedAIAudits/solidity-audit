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
import typing
import bittensor as bt
from dotenv import load_dotenv

from model_servers.subnet_utils import create_session
from neurons.base import ReinforcedMinerNeuron
from ai_audits.protocol import AuditsSynapse, VulnerabilityReport


class Miner(ReinforcedMinerNeuron):
    REQUEST_PERIOD = 20 * 60
    _last_call_from_dendrite: dict[str, float]
    _dendrite_whitelist: list[str]

    def __init__(self, config=None):
        super(Miner, self).__init__(config=config)
        self._last_call_from_dendrite = {}
        self._dendrite_whitelist = [
            key.strip()
            for key in os.getenv("DENDRITE_WHITELIST", "").split(",")
            if key.strip()
        ]
        self.load_website_keys()
        self.set_identity()

    def load_website_keys(self):
        try:
            keys_response = create_session().get("https://audit.reinforced.app/keys")
            if keys_response.status_code == 200:
                keys_list = keys_response.json()
                if isinstance(keys_list, list) and all(
                    isinstance(key, str) for key in keys_list
                ):
                    self._dendrite_whitelist = list(
                        set(self._dendrite_whitelist) | set(keys_list)
                    )
                else:
                    bt.logging.error(f"key list has invalid format: {keys_list}")
            else:
                bt.logging.info(
                    f"Something went wrong with the key service. Status code: {keys_response.status_code}"
                )
        except Exception as e:
            bt.logging.error(f"An error occurred while connection to key service: {e}")

    async def forward(self, synapse: AuditsSynapse) -> AuditsSynapse:
        """
        Processes the incoming synapse by performing a predefined operation on the input data.
        """
        bt.logging.info(f"Received synapse from validator {synapse}")
        result = create_session().post(
            f"{os.getenv('MINER_SERVER')}/submit",
            synapse.contract_code,
            headers={"Content-Type": "text/plain"},
        )
        # TODO: Remove the error and allow sending a synapse with an empty response + log this event
        if result.status_code != 200:
            bt.logging.info(f"Not successful AI response. Description: {result.text}")
            raise ValueError("Contract audit is not successful!")

        json = result.json()
        bt.logging.info(f"Response from miner server: {json}")
        vulnerabilities = [
            VulnerabilityReport(
                **vuln,
            )
            for vuln in json
        ]

        synapse.response = vulnerabilities
        return synapse

    async def blacklist(self, synapse: AuditsSynapse) -> typing.Tuple[bool, str]:
        """
        Determines whether an incoming request should be blacklisted and thus ignored.
        """
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            bt.logging.warning("Received a request without a dendrite or hotkey.")
            return True, "Missing dendrite or hotkey"

        if synapse.dendrite.hotkey in self._dendrite_whitelist:
            return False, f"Hotkey {synapse.dendrite.hotkey} is whitelisted"
        # TODO(developer): Define how miners should blacklist requests.
        uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        if (
            not self.config.blacklist.allow_non_registered
            and synapse.dendrite.hotkey not in self.metagraph.hotkeys
        ):
            # Ignore requests from un-registered entities.
            bt.logging.trace(
                f"Blacklisting un-registered hotkey {synapse.dendrite.hotkey}"
            )
            return True, "Unrecognized hotkey"

        current_time = time.time()

        if synapse.dendrite.hotkey in self._last_call_from_dendrite:
            time_since_last_request = (
                current_time - self._last_call_from_dendrite[synapse.dendrite.hotkey]
            )

            if time_since_last_request < self.REQUEST_PERIOD:
                return (
                    True,
                    f"Request submitted too soon. {int(self.REQUEST_PERIOD - time_since_last_request)} second(s) left until the next request is allowed. Dendrite's associated hotkey: {synapse.dendrite.hotkey}",
                )

        self._last_call_from_dendrite[synapse.dendrite.hotkey] = current_time

        if self.config.blacklist.force_validator_permit:
            # If the config is set to force validator permit, then we should only allow requests from validators.
            if not self.metagraph.validator_permit[uid]:
                bt.logging.warning(
                    f"Blacklisting a request from non-validator hotkey {synapse.dendrite.hotkey}"
                )
                return True, "Non-validator hotkey"

        bt.logging.trace(
            f"Not Blacklisting recognized hotkey {synapse.dendrite.hotkey}"
        )
        return False, "Hotkey recognized!"

    async def priority(self, synapse: AuditsSynapse) -> float:
        """
        The priority function determines the order in which requests are handled. More valuable or higher-priority
        requests are processed before others.
        """
        if synapse.dendrite is None or synapse.dendrite.hotkey is None:
            bt.logging.warning("Received a request without a dendrite or hotkey.")
            return 0.0

        if synapse.dendrite.hotkey in self._dendrite_whitelist:
            return self.metagraph.S.max() + 1.0

        # TODO(developer): Define how miners should prioritize requests.
        caller_uid = self.metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        priority = float(
            self.metagraph.S[caller_uid]
        )  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: {priority}"
        )
        return priority


# This is the main function, which runs the miner.
if __name__ == "__main__":
    load_dotenv()
    with Miner() as miner:
        while True:
            bt.logging.info(f"Miner running... {time.time()}")
            time.sleep(1200)
