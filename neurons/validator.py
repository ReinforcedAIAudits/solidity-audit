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
import copy
import math
import os
import pickle
from random import choices
import time
import traceback
from typing import List

import bittensor as bt
from bittensor.utils.btlogging import logging
from dotenv import load_dotenv


from ai_audits.nft_protocol import MedalRequestsMessage
from ai_audits.protocol import AuditsSynapse, VulnerabilityReport, ValidatorTask, TaskType
from ai_audits.subnet_utils import create_session, is_synonyms, get_invalid_code
from neurons.base import ReinforcedValidatorNeuron, get_random_uids, ScoresBuffer

load_dotenv()
CYCLE_TIME = int(os.getenv("VALIDATOR_SEND_REQUESTS_EVERY_X_SECS", "3600"))


class Validator(ReinforcedValidatorNeuron):
    WEIGHT_TIME = 0.1
    WEIGHT_ONLY_SCORE = 0.9

    MAX_BUFFER = int(os.getenv("VALIDATOR_BUFFER", "100"))

    def __init__(self, config=None):
        self._step = 0
        self._start_time = time.time()
        self._validator_time_min = (
            int(os.getenv("VALIDATOR_TIME"))
            if os.getenv("VALIDATOR_TIME") and 0 <= int(os.getenv("VALIDATOR_TIME")) <= 59
            else None
        )

        self._buffer_scores = ScoresBuffer(self.MAX_BUFFER)
        super().__init__(config=config)
        self.set_identity()

    @classmethod
    def get_audit_task(cls, vulnerability_type: str | None = None) -> ValidatorTask:
        task_type = choices(list(TaskType), [70, 25, 5])[0]
        if task_type == TaskType.RANDOM_TEXT:
            return get_invalid_code()
        result = create_session().post(
            f"{os.getenv('MODEL_SERVER')}/{task_type}",
            *([] if vulnerability_type is None else [vulnerability_type]),
            headers={"Content-Type": "text/plain"},
        )

        if result.status_code != 200:
            logging.info(f"Not successful AI response. Description: {result.text}")
            raise ValueError("Unable to receive task from MODEL_SERVER!")

        json = result.json()
        logging.info(f"Response from model server: {json}")
        task = ValidatorTask(task_type=task_type, **json)
        return task

    def sync(self):
        if self.step == 0:
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
        self.synchronise_state()
        miner_uids = self.metagraph.n.item()
        logging.info(f"Metagraph uids: {miner_uids}")
        active_uids = [index for index, is_active in enumerate(self.metagraph.active) if is_active == 1]
        logging.info(f"Active UIDs: {active_uids}")
        axon_count = len(self.metagraph.axons) - 1

        miner_selection_size = min(axon_count, self.config.neuron.sample_size)
        miner_uids = get_random_uids(self, k=miner_selection_size, exclude=[self.uid])

        logging.info(f"Selected UIDs: {miner_uids}")
        logging.info(f"Self UID: {self.uid}")

        max_retries_to_get_tasks = 10
        retry_delay = 10

        for attempt in range(max_retries_to_get_tasks):
            try:
                task = self.get_audit_task()
                logging.info(f"task: {task}")
                break
            except ValueError as e:
                logging.warning(f"Attempt {attempt + 1}/{max_retries_to_get_tasks} failed: {str(e)}")
                if attempt < max_retries_to_get_tasks - 1:
                    logging.info(f"Waiting {retry_delay} seconds before next attempt...")
                    await asyncio.sleep(retry_delay)
                else:
                    logging.error("Max retries reached. Unable to get audit task.")
                    return

        if os.getenv("RUN_LOCAL", "").lower() != "true":
            self.dendrite.external_ip = "127.0.0.1"

        synapse = AuditsSynapse(contract_code=task.contract_code)
        logging.info(f"Axons: {self.metagraph.axons}")

        responses = await self.dendrite.aquery(
            axons=[self.metagraph.axons[uid] for uid in miner_uids],
            synapse=synapse,
            deserialize=False,
            timeout=600,
        )
        logging.info(f"Received responses: {[resp.response for resp in responses]}")

        rewards = self.validate_responses(responses, task, self.axon.info().hotkey)

        logging.info(f"Scored responses: {rewards}")

        try:
            self.send_top_miners(responses, rewards, miner_uids)
        except Exception as e:
            logging.error(f"Unable to send top miners: {str(e)}")

        for num, uid in enumerate(miner_uids):
            self._buffer_scores.add_score(uid, rewards[num])

        await self.dendrite.aclose_session()

        self.update_scores(rewards, miner_uids)

    def run(self):
        """
        Initiates and manages the main loop for the miner on the Bittensor network. The main loop handles graceful shutdown on keyboard interrupts and logs unforeseen errors.

        This function performs the following primary tasks:
        1. Check for registration on the Bittensor network.
        2. Continuously forwards queries to the miners on the network, rewarding their responses and updating the scores accordingly.
        3. Periodically resynchronizes with the chain; updating the metagraph with the latest network state and setting weights.

        The essence of the validator's operations is in the forward function, which is called every step. The forward function is responsible for querying the network and scoring the responses.

        Note:
            - The function leverages the global configurations set during the initialization of the miner.
            - The miner's axon serves as its interface to the Bittensor network, handling incoming and outgoing requests.

        Raises:
            KeyboardInterrupt: If the miner is stopped by a manual interruption.
            Exception: For unforeseen errors during the miner's operation, which are logged for diagnosis.
        """

        # Check that validator is registered on the network.
        self.sync()

        logging.info(f"Validator starting at block: {self.block}")

        # This loop maintains the validator's operations until intentionally stopped.
        try:
            while True:
                logging.info(f"step({self.step}) block({self.block})")

                # Run multiple forwards concurrently.
                self.loop.run_until_complete(self.concurrent_forward())

                # Check if we should exit.
                if self.should_exit:
                    break

                # Sync metagraph and potentially set weights.
                self.sync()

                self.step += 1

        except KeyboardInterrupt:
            self.axon.stop()
            logging.success("Validator killed by keyboard interrupt.")
            exit()

        except Exception as err:
            logging.error(f"Validator killed due to exception: {traceback.format_exception(err)}")
            exit(1)

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
            logging.info("set_weights on chain successfully!")
        else:
            logging.error("set_weights failed", msg)

    @classmethod
    def _get_min_response_time(cls, responses: List[AuditsSynapse], self_hotkey: str = "") -> float:
        """Helper method to get minimum response time from valid dendrites."""
        valid_times = [
            x.dendrite.process_time
            for x in responses
            if x.dendrite.process_time is not None and x.axon.hotkey != self_hotkey
        ]
        return min(valid_times) if valid_times else 0.0

    @classmethod
    def _calculate_time_score(cls, synapse: AuditsSynapse, min_time: float, self_hotkey: str = "") -> float:
        """Calculate score based on response time."""
        if not synapse.dendrite.process_time or synapse.axon.hotkey == self_hotkey:
            return 0
        return min_time / synapse.dendrite.process_time

    @classmethod
    def validate_responses(
        cls,
        responses: List[AuditsSynapse],
        task: ValidatorTask = None,
        self_hotkey: str = "",
    ) -> List[float]:
        min_time = cls._get_min_response_time(responses, self_hotkey)
        scores = []

        for synapse in responses:
            logging.debug(
                f"Synapse: axon hotkey: {synapse.axon.hotkey} | is success: {synapse.is_success} | "
                f"is blacklisted: {synapse.is_blacklist} | message: {synapse.axon.status_message}"
            )

            report_score = cls.validate_reports_by_reference(synapse.response, task) * cls.WEIGHT_ONLY_SCORE
            time_score = (
                cls._calculate_time_score(synapse, min_time, self_hotkey)
                * (report_score / cls.WEIGHT_ONLY_SCORE)
                * cls.WEIGHT_TIME
            )
            logging.debug(f"Process time: {synapse.dendrite.process_time}")
            logging.debug(f"Report score: {report_score}, Time score: {time_score}")
            scores.append(report_score + time_score)

        logging.debug(f"Final scores: {scores}")
        return scores

    @classmethod
    def validate_times(cls, responses: List[AuditsSynapse], self_hotkey: str = "") -> List[float]:
        min_time = cls._get_min_response_time(responses, self_hotkey)
        scores = [cls._calculate_time_score(synapse, min_time, self_hotkey) for synapse in responses]
        logging.debug(f"Time scores: {scores}")
        return scores

    def assign_achievements(self, rewards: List[float], uids: List[int], achievement_count: int = 3):
        top_scores = sorted(enumerate(rewards), key=lambda x: x[1], reverse=True)[:achievement_count]
        return [uids[index] for index, _ in top_scores]

    def create_top_miners(self, responses: List[AuditsSynapse], rewards: List[float], uids: List[int]):
        top_miners = self.assign_achievements(rewards, uids)
        achievements = {1: "Gold", 2: "Silver", 3: "Bronze"}
        result_top = []
        for place, uid in enumerate(top_miners):
            synapse = next((x for x in responses if x.axon.hotkey == self.metagraph.axons[uid].hotkey), None)
            if synapse:
                message = MedalRequestsMessage(
                    medal=achievements[place + 1],
                    miner_ss58_hotkey=synapse.axon.hotkey,
                    score=rewards[uids.index(uid)],
                )
                message.sign(self.wallet.coldkey)
                result_top.append(message)
        logging.info(f"Top miners: {result_top}")
        return result_top

    def send_top_miners(self, responses: List[AuditsSynapse], rewards: List[float], uids: List[int]):
        top_miners = self.create_top_miners(responses, rewards, uids)
        result = create_session().post(
            f"{os.getenv('WEBSITE_URL')}/api/mint_medals",
            json=[miner.model_dump() for miner in top_miners],
            headers={"Content-Type": "application/json"},
        )
        if result.status_code != 200:
            logging.info(f"Not successful setting top miners. Description: {result.text}")
            raise ValueError("Unable to set top miners!")
        logging.info(f"Top miners set successfully.")

    @classmethod
    def _get_replaced_keys(cls, old_state: list[str], new_state: list[str]) -> list[int]:
        min_length = min(len(old_state), len(new_state))
        return [netuid for netuid in range(min_length) if old_state[netuid] != new_state[netuid]]

    @classmethod
    def validate_reports_by_reference(
        cls,
        report: List[VulnerabilityReport] | None,
        task: ValidatorTask,
    ) -> float:
        if report is None or not task:
            return 0.0

        def sigmoid(x, k=25, x0=0.225):
            return 1 / (1 + math.exp(-k * (x - x0)))

        vulnerabilities_found = {x.vulnerability_class.lower() for x in report}
        matching_vulns = {v for v in vulnerabilities_found if is_synonyms(task.vulnerability_class, v)}

        if matching_vulns:
            excess_vulns = vulnerabilities_found - matching_vulns
            excess_ratio = len(excess_vulns) / len(vulnerabilities_found)

            excess_penalty = sigmoid(excess_ratio, k=15, x0=3 / 4)
            score = 1 - excess_penalty
        else:
            score = 0.0

        if task.task_type == TaskType.HYBRID:
            lines_of_code = len(task.contract_code.split("\n"))
            vuln_lines = {i for i in range(task.from_line, task.to_line + 1)}
            health_code_lines_number = lines_of_code - len(vuln_lines)

            reported_lines = set()
            for r in report:
                reported_lines |= {i for i in range(r.from_line, r.to_line + 1)}

            missed_lines = len(reported_lines - vuln_lines)
            missed_ratio_to_health_code = missed_lines / health_code_lines_number
            missed_lines_penalty = sigmoid(missed_ratio_to_health_code)

            precision = len(vuln_lines & reported_lines) / len(reported_lines) if reported_lines else 0
            recall = len(vuln_lines & reported_lines) / len(vuln_lines) if vuln_lines else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            score = (score + f1_score * (1 - missed_lines_penalty)) / 2

        return score

    # TODO: This function is currently unused, but may be useful in the future.
    #  Consider re-evaluating its necessity before removing.
    @classmethod
    def validate_report(cls, report: VulnerabilityReport, task: ValidatorTask) -> float:
        if is_synonyms(task.vulnerability_class, report.vulnerability_class):
            return 1.0
        else:
            return 0.0

    def synchronise_state(self):
        old_hotkeys = copy.deepcopy(self.hotkeys)
        self.metagraph.sync(subtensor=self.subtensor)
        self.hotkeys = copy.deepcopy(self.metagraph.hotkeys)
        replaced_keys = self._get_replaced_keys(old_hotkeys, self.hotkeys)
        for key in replaced_keys:
            self._buffer_scores.reset(key)
            self.scores[key] = 0
            logging.info("Synchronise state: uid f{key} was replaced: f{old_hotkeys[key]} -> f{self.hotkeys[key]}")
        if replaced_keys:
            self.save_state()

    def save_state(self):
        """Saves the state of the validator to a file."""
        logging.info("Saving validator state.")

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
        logging.info("Loading validator state.")
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
            logging.error("State file is not found.")
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
            logging.info(f"Validator running... {time.time()}")
            time.sleep(1200)
