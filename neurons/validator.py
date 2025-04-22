import dataclasses
import json
import logging
import math
import os
import time
from concurrent.futures import ThreadPoolExecutor
from random import choices

import requests
from dotenv import load_dotenv
from solidity_audit_lib import SubtensorWrapper
from solidity_audit_lib.encrypting import decrypt
from solidity_audit_lib.messaging import VulnerabilityReport, ContractTask, MinerResponseMessage, MinerResponse
from solidity_audit_lib.relayer_client.relayer_types import ValidatorStorage
from unique_playgrounds import UniqueHelper

from ai_audits.nft_protocol import MedalRequestsMessage
from ai_audits.protocol import ValidatorTask, TaskType, MinerInfo, NFTMetadata
from ai_audits.subnet_utils import create_session, is_synonyms, get_invalid_code
from neurons.base import ReinforcedNeuron, ScoresBuffer, ReinforcedConfig, ReinforcedError

load_dotenv()


__all__ = ["Validator", "MinerResult"]


@dataclasses.dataclass
class MinerResult:
    uid: int
    time: float
    response: list[VulnerabilityReport] | None


class Validator(ReinforcedNeuron):
    MODE_RAW = "raw"
    MODE_RELAYER = "relayer"
    NEURON_TYPE = "validator"

    WEIGHT_TIME = 0.1
    WEIGHT_ONLY_SCORE = 0.9
    CYCLE_TIME = int(os.getenv("VALIDATOR_SEND_REQUESTS_EVERY_X_SECS", "3600"))

    MAX_BUFFER = int(os.getenv("VALIDATOR_BUFFER", "24"))
    MINER_CHECK_TIMEOUT = 5
    MINER_RESPONSE_TIMEOUT = 2 * 60

    def __init__(self, config: ReinforcedConfig):
        super().__init__(config)
        self.ip = "0.0.0.0"
        self.port = 1
        self._last_validation = 0
        self._validator_time_min = (
            int(os.getenv("VALIDATOR_TIME"))
            if os.getenv("VALIDATOR_TIME") and 0 <= int(os.getenv("VALIDATOR_TIME")) <= 59
            else None
        )

        self._buffer_scores = ScoresBuffer(self.MAX_BUFFER)
        self.hotkeys = {}
        self.load_state()
        self.mode = self.MODE_RELAYER
        self.log.info(f"Validator running in {self.mode} mode")

    def get_audit_task(self, vulnerability_type: str | None = None) -> ValidatorTask:
        task_type = choices(list(TaskType), [60, 25, 5, 10])[0]
        if task_type == TaskType.RANDOM_TEXT:
            return get_invalid_code()
        result = create_session().post(
            f"{os.getenv('MODEL_SERVER')}/{task_type}",
            *([] if vulnerability_type is None else [vulnerability_type]),
            headers={"Content-Type": "text/plain"},
        )

        if result.status_code != 200:
            self.log.info(f"Not successful AI response. Description: {result.text}")
            raise ValueError("Unable to receive task from MODEL_SERVER!")

        result_json = result.json()
        self.log.info(f"Response from model server: {result_json}")
        task = ValidatorTask(task_type=task_type, **result_json)
        return task

    def try_get_task(self) -> ValidatorTask | None:
        max_retries_to_get_tasks = 10
        retry_delay = 10
        for attempt in range(max_retries_to_get_tasks):
            try:
                return self.get_audit_task()
            except ValueError as e:
                self.log.warning(f"Attempt {attempt + 1}/{max_retries_to_get_tasks} failed: {str(e)}")
                if attempt < max_retries_to_get_tasks - 1:
                    self.log.info(f"Waiting {retry_delay} seconds before next attempt...")
                    time.sleep(retry_delay)
                else:
                    self.log.error("Max retries reached. Unable to get audit task.")
                    return None
        return None

    def remove_dead_miners(self, miners: list[MinerInfo]) -> list[MinerInfo]:
        to_check = [(x.uid, x.ip, x.port) for x in miners]
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.is_miner_alive, *args) for args in to_check]
            results = [future.result() for future in futures]
        valid_miner_uids = [uid for uid, is_valid in results if is_valid]
        self.log.info(f"Active miner uids: {valid_miner_uids}")
        return [x for x in miners if x.uid in valid_miner_uids]

    def get_miners_raw(self) -> list[MinerInfo]:
        axons = [
            MinerInfo(uid=uid, hotkey=axon["hotkey"], ip=axon["info"]["ip"], port=axon["info"]["port"])
            for uid, axon in enumerate(self.get_axons())
        ]
        axons = [x for x in axons if x.hotkey != self.hotkey.ss58_address]
        return self.remove_dead_miners(axons)

    def get_miners_from_relayer(self) -> list[MinerInfo]:
        miners = [
            MinerInfo(uid=miner.uid, hotkey=miner.hotkey, ip=miner.ip, port=miner.port)
            for miner in self.relayer_client.get_miners(self.hotkey)
        ]
        return miners

    def get_miners(self) -> list[MinerInfo]:
        if self.mode == self.MODE_RAW:
            return self.get_miners_raw()
        return self.get_miners_from_relayer()

    def is_miner_alive(self, uid: int, ip_address: str, port: int) -> tuple[int, bool]:
        try:
            response = requests.get(f"http://{ip_address}:{port}/miner_running", timeout=self.MINER_CHECK_TIMEOUT)
            return uid, response.status_code == 200  and response.json()["status"] == "OK"
        except Exception as e:
            self.log.info(f"Error checking uid {uid}: {e}")
            return uid, False


    def check_tokens(self, response: MinerResponse, task: ValidatorTask) -> bool:
        token = None
        if not response.token_ids:
            self.log.error(f"Tokens for miner {response.ss58_address} not found")
            return False

        for token_id in response.token_ids:
            with UniqueHelper(self.settings.unique_endpoint) as helper:
                token = (helper.nft.get_token_info(response.collection_id, token_id))

            if not token:
                self.log.error(f"Token {token_id} for miner {response.ss58_address} not found")
                return False

            properties = {x["key"]: x["value"] for x in token["properties"]}

            if properties["validator"] != self.hotkey.ss58_address:
                self.log.error(f"Token {token_id} for miner {response.ss58_address} has incorrect validator")
                return False

            try:
                metadata = NFTMetadata(**json.loads(decrypt(properties["audit"][2:], self.crypto_hotkey, response.ss58_address)))
            except Exception as e:
                self.log.error(f"Error decrypting token {token_id} for miner {response.ss58_address}: {e}")
                return False

            if metadata.task != task.contract_code:
                self.log.error(f"Token {token_id} for miner {response.ss58_address} has incorrect task")
                return False

            if metadata.miner_info.uid != response.uid:
                self.log.error(f"Token {token_id} for miner {response.ss58_address} has incorrect miner info")
                return False

            response_vulns = {x.vulnerability_class for x in response.report if not x.is_suggestion}
            vulns_in_nft = {x.vulnerability_class for x in metadata.audit if not x.is_suggestion}

            if vulns_in_nft != response_vulns:
                self.log.warning(f"Token {token_id} for miner {response.ss58_address} has incorrect data")
                return False

        return True

    def ask_miner(self, miner: MinerInfo, task: ValidatorTask) -> MinerResult:
        start_time = time.time()
        response = None
        try:
            miner_task = ContractTask(uid=miner.uid, contract_code=task.contract_code)

            miner_task.sign(self.hotkey)

            task_json = miner_task.model_dump()

            result = requests.post(
                f"http://{miner.ip}:{miner.port}/forward", json=task_json, timeout=self.MINER_RESPONSE_TIMEOUT
            ).json()

            response: MinerResponseMessage = MinerResponseMessage(**result)

            if not self.check_nft_collection_ownership(response.result.collection_id, response.ss58_address):
                self.log.error(f"Collection is not minted for uid {miner.uid}")
                return MinerResult(uid=miner.uid, time=abs(time.time() - start_time), response=None)

            if not self.check_tokens(response.result, task):
                self.log.error(f"Token is not minted for uid {miner.uid}")
                return MinerResult(uid=miner.uid, time=abs(time.time() - start_time), response=None)

        except Exception as e:
            self.log.info(f"Error asking miner {miner.uid} ({miner.ip}:{miner.port}): {e}")
        return MinerResult(
            uid=miner.uid,
            time=abs(time.time() - start_time),
            response=response.result.report if response.result else None,
        )

    def ask_miners_raw(self, miners: list[MinerInfo], task: ValidatorTask) -> list[MinerResult]:
        to_check = [(x, task) for x in miners]
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.ask_miner, *args) for args in to_check]
            results = [future.result() for future in futures]
        return results

    def ask_miner_relay(self, miner: MinerInfo, task: ValidatorTask) -> MinerResult:
        start_time = time.time()
        try:
            result = self.relayer_client.perform_audit(self.hotkey, miner.uid, task.contract_code)
        except Exception as e:
            self.log.error(f"Error performing audit {miner.uid}: {e}")
            return MinerResult(uid=miner.uid, time=abs(time.time() - start_time), response=None)

        elapsed_time = time.time() - start_time

        if not result.success:
            self.log.error(f"Error asking miner {miner.uid}: {result.error}")
            return MinerResult(uid=miner.uid, time=elapsed_time, response=None)

        response = result.result
        self.log.debug(response)
        if not response.verify():
            self.log.error(f"Response from miner {miner.uid} has incorrect signature")
            return MinerResult(uid=miner.uid, time=elapsed_time, response=None)

        if not self.check_nft_collection_ownership(response.collection_id, response.ss58_address):
            self.log.error(f"Collection is not minted for uid {miner.uid}")
            return MinerResult(uid=miner.uid, time=elapsed_time, response=None)

        if not self.check_tokens(response, task):
            self.log.error(f"Token is not minted for uid {miner.uid}")
            return MinerResult(uid=miner.uid, time=elapsed_time, response=None)

        return MinerResult(uid=miner.uid, time=elapsed_time, response=response.report)

    def ask_miners_relay(self, miners: list[MinerInfo], task: ValidatorTask) -> list[MinerResult]:
        to_check = [(x, task) for x in miners]
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.ask_miner_relay, *args) for args in to_check]
            results = [future.result() for future in futures]
        return results

    def ask_miners(self, miners: list[MinerInfo], task: ValidatorTask) -> list[MinerResult]:
        if self.mode == self.MODE_RAW:
            return self.ask_miners_raw(miners, task)
        return self.ask_miners_relay(miners, task)

    def clear_scores_for_old_hotkeys(self):
        old_hotkeys = self.hotkeys.copy()
        new_hotkeys = {uid: axon["hotkey"] for uid, axon in enumerate(self.get_axons())}
        for uid, key in old_hotkeys.items():
            if key != new_hotkeys[uid]:
                self._buffer_scores.reset(uid)
        self.hotkeys = new_hotkeys

    @classmethod
    def remove_suggestions(cls, miner_answer: MinerResult):
        if miner_answer.response is None:
            return miner_answer
        return MinerResult(
            uid=miner_answer.uid,
            time=miner_answer.time,
            response=[x for x in miner_answer.response if not x.is_suggestion],
        )

    def validate(self):
        miners = self.get_miners()
        self.log.info("Miners list received")
        if not miners:
            self.log.warning("No active miners, validator would skip this loop")
            return
        task = self.try_get_task()
        self.log.info("Task for miners received")
        if task is None:
            self.log.error("Unable to get task. Check your settings")
            raise ReinforcedError("Unable to get task")
        self.log.debug(f"Validator task:\n{task}")
        self.log.debug(f"Active miners uids: {[x.uid for x in miners]}")
        responses = self.ask_miners(miners, task)
        responses = [self.remove_suggestions(x) for x in responses]
        self.log.info("Miners responses received")

        rewards = self.validate_responses(responses, task, miners)

        self.log.info(f"Scored responses: {rewards}")

        try:
            self.send_top_miners(rewards, miners)
        except Exception as e:
            self.log.error(f"Unable to send top miners: {str(e)}")

        for num, miner in enumerate(miners):
            self._buffer_scores.add_score(miner.uid, rewards[num])

        self.set_weights()

    def run(self):
        while True:
            self.log.info("Validator loop is running")
            sleep_time = self.get_sleep_time()
            if sleep_time:
                self.log.info(f"Validator will sleep {sleep_time} secs until next loop. Zzz...")
                time.sleep(sleep_time)
            self.clear_scores_for_old_hotkeys()
            self.check_axon_alive()
            self.validate()
            self._last_validation = time.time()
            self.save_state()

    def set_weights(self):
        with SubtensorWrapper(self.config.ws_endpoint) as client:
            result, error = client.set_weights(
                self.hotkey, self.config.net_uid, dict(zip(self._buffer_scores.uids(), self._buffer_scores.scores()))
            )
        if result:
            self.log.info("set_weights on chain successfully!")
        elif error["name"] == "RateLimit":
            self.log.warning("set_weights failed due to rate limit, will retry later.")
            time.sleep(12 * error["blocks"])
            self.set_weights()
        else:
            self.log.error(f"set_weights failed: {error}")

    @classmethod
    def _get_min_response_time(cls, responses: list[MinerResult]) -> float:
        """Helper method to get minimum response time from valid dendrites."""
        valid_times = [x.time for x in responses if x.response is not None]
        return min(valid_times) if valid_times else 0.0

    @classmethod
    def _calculate_time_score(cls, result: MinerResult, min_time: float) -> float:
        """Calculate score based on response time."""
        if result.response is None or not result.time:
            return 0
        return min_time / result.time

    @classmethod
    def validate_responses(
        cls,
        results: list[MinerResult],
        task: ValidatorTask,
        miners: list[MinerInfo],
        log: logging.Logger = logging.getLogger("empty"),
    ) -> list[float]:
        min_time = cls._get_min_response_time(results)
        scores = []
        results_by_uid = {x.uid: x for x in results}
        for miner in miners:
            result = results_by_uid[miner.uid]
            if result.response is None:
                log.debug(f"Invalid response from uid {miner.uid}")
                scores.append(0)
                continue

            report_score = cls.validate_reports_by_reference(result.response, task) * cls.WEIGHT_ONLY_SCORE
            time_score = (
                cls._calculate_time_score(result, min_time) * (report_score / cls.WEIGHT_ONLY_SCORE) * cls.WEIGHT_TIME
            )
            log.debug(f"Miner uid: {miner.uid}, hotkey: {miner.hotkey}")
            log.debug(f"Process time: {result.time}")
            log.debug(f"Report score: {report_score}, Time score: {time_score}")
            scores.append(report_score + time_score)

        log.debug(f"Final scores: {scores}")
        return scores

    @classmethod
    def assign_achievements(
        cls, rewards: list[float], miners: list[MinerInfo], achievement_count: int = 3
    ) -> list[MinerInfo]:
        top_scores = sorted(enumerate(rewards), key=lambda x: x[1], reverse=True)[:achievement_count]
        return [miners[index] for index, _ in top_scores]

    def create_top_miners(self, rewards: list[float], miners: list[MinerInfo]):
        miner_rewards = dict(zip([x.uid for x in miners], rewards))
        top_miners = self.assign_achievements(rewards, miners)
        achievements = {1: "Gold", 2: "Silver", 3: "Bronze"}
        result_top = []
        for place, miner in enumerate(top_miners):
            message = MedalRequestsMessage(
                medal=achievements[place + 1],
                miner_ss58_hotkey=miner.hotkey,
                score=miner_rewards[miner.uid],
            )
            message.sign(self.hotkey)
            result_top.append(message)
        self.log.info(f"Top miners: {result_top}")
        return result_top

    def send_top_miners(self, rewards: list[float], miners: list[MinerInfo]):
        top_miners = self.create_top_miners(rewards, miners)
        if not top_miners:
            self.log.warning("No top miners during this validation")
        result = create_session().post(
            f"{os.getenv('WEBSITE_URL', 'https://audit.reinforced.app')}/api/mint_medals",
            json=[miner.model_dump() for miner in top_miners],
            headers={"Content-Type": "application/json"},
        )
        if result.status_code != 200:
            self.log.info(f"Not successful setting top miners. Description: {result.text}")
            raise ValueError("Unable to set top miners!")
        self.log.info(f"Top miners set successfully.")

    @classmethod
    def validate_reports_by_reference(
        cls,
        report: list[VulnerabilityReport] | None,
        task: ValidatorTask,
    ) -> float:
        if report is None or not task:
            return 0.0

        def sigmoid(x, k=25, x0=0.225):
            return 1 / (1 + math.exp(-k * (x - x0)))

        vulnerabilities_found = {x.vulnerability_class.lower() for x in report}
        matching_vulns = {v for v in vulnerabilities_found if is_synonyms(task.vulnerability_class, v)}

        if task.task_type == TaskType.VALID_CONTRACT and len(vulnerabilities_found) == 0:
            score = 1.0
        elif matching_vulns:
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

    def save_state(self):
        self.log.info("Saving validator state.")

        self.relayer_client.set_storage(
            self.hotkey,
            ValidatorStorage(
                last_validation=int(self._last_validation),
                scores=self._buffer_scores.dump(),
                hotkeys={str(k): v for k, v in self.hotkeys.items()},
            ),
        )

    def load_state(self):
        self.log.info("Loading validator state.")
        storage = self.relayer_client.get_storage(self.hotkey)
        if storage.success and storage.result is not None and "last_validation" in storage.result:
            state = ValidatorStorage(**storage.result)

            buf = ScoresBuffer(self.MAX_BUFFER)
            buf.load(state.scores)
            self._buffer_scores = buf
            self._last_validation = state.last_validation
            self.hotkeys = {int(uid): hotkey for uid, hotkey in state.hotkeys.items()}
        else:
            self.save_state()

    def get_sleep_time(self) -> int | float:
        if self._validator_time_min:
            current_minute = int(time.strftime("%M"))
            if current_minute == self._validator_time_min:
                wait_time_min = 60
            else:
                wait_time_min = (self._validator_time_min - current_minute) % 60
            return wait_time_min * 60

        elapsed_time = time.time() - self._last_validation
        if elapsed_time < self.CYCLE_TIME:
            return self.CYCLE_TIME - elapsed_time
        return 0


if __name__ == "__main__":
    config = ReinforcedConfig(
        ws_endpoint=os.getenv("CHAIN_ENDPOINT", "wss://test.finney.opentensor.ai:443"),
        net_uid=int(os.getenv("NETWORK_UID", "222")),
    )
    validator = Validator(config)
    if not validator.wait_for_server(os.getenv("MODEL_SERVER", "http://localhost:5001")):
        validator.log.error("Model server is not available. Exiting.")
        exit(1)

    validator.serve_axon()
    validator.run()
