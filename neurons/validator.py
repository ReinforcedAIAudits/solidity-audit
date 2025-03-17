import dataclasses
import logging
from concurrent.futures import ThreadPoolExecutor
import math
import os
import pickle
from random import choices
import time

from dotenv import load_dotenv
import requests

from ai_audits.nft_protocol import MedalRequestsMessage
from ai_audits.protocol import VulnerabilityReport, ValidatorTask, TaskType, ContractTask
from ai_audits.subnet_utils import create_session, is_synonyms, get_invalid_code
from ai_audits.subtensor_wrapper import SubtensorWrapper
from neurons.base import ReinforcedNeuron, ScoresBuffer, ReinforcedConfig, ReinforcedError

load_dotenv()


__all__ = ['Validator', 'MinerInfo', 'MinerResult']


@dataclasses.dataclass
class MinerInfo:
    uid: int
    ip: str
    port: int
    hotkey: str


@dataclasses.dataclass
class MinerResult:
    uid: int
    time: float
    response: list[VulnerabilityReport] | None

# TODO is active in validate()

class Validator(ReinforcedNeuron):
    MODE_RAW = 'raw'
    MODE_RELAYER = 'relayer'

    WEIGHT_TIME = 0.1
    WEIGHT_ONLY_SCORE = 0.9
    CYCLE_TIME = int(os.getenv("VALIDATOR_SEND_REQUESTS_EVERY_X_SECS", "3600"))

    MAX_BUFFER = int(os.getenv("VALIDATOR_BUFFER", "24"))
    MINER_CHECK_TIMEOUT = 5
    MINER_RESPONSE_TIMEOUT = 2 * 60

    def __init__(self, config: ReinforcedConfig):
        super().__init__(config)
        self._last_validation = 0
        self._validator_time_min = (
            int(os.getenv("VALIDATOR_TIME"))
            if os.getenv("VALIDATOR_TIME") and 0 <= int(os.getenv("VALIDATOR_TIME")) <= 59
            else None
        )

        self._buffer_scores = ScoresBuffer(self.MAX_BUFFER)
        self.set_identity()
        self.hotkeys = {}
        self.load_state()
        self.mode = self.MODE_RAW
        self.log.info(f'Validator running in {self.mode} mode')

    def get_audit_task(self, vulnerability_type: str | None = None) -> ValidatorTask:
        task_type = choices(list(TaskType), [70, 25, 5])[0]
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

        json = result.json()
        self.log.info(f"Response from model server: {json}")
        task = ValidatorTask(task_type=task_type, **json)
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

    def get_miners_raw(self) -> list[MinerInfo]:
        axons = [
            MinerInfo(uid=uid, hotkey=axon['hotkey'], ip=axon['info']['ip'], port=axon['info']['port'])
            for uid, axon in enumerate(self.get_axons())
        ]
        axons = [x for x in axons if x.hotkey != self.hotkey.ss58_address]
        to_check = [(x.uid, x.ip, x.port) for x in axons]
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.is_miner_alive, *args) for args in to_check]
            results = [future.result() for future in futures]
        valid_miner_uids = [uid for uid, is_valid in results if is_valid]
        self.log.info(f'Active miner uids: {valid_miner_uids}')
        return [x for x in axons if x.uid in valid_miner_uids]

    def get_miners_from_relayer(self) -> list[MinerInfo]:
        return []

    def get_miners(self) -> list[MinerInfo]:
        if self.mode == self.MODE_RAW:
            return self.get_miners_raw()
        return self.get_miners_from_relayer()

    def is_miner_alive(self, uid: int, ip_address: str, port: int) -> tuple[int, bool]:
        try:
            response = requests.get(f'http://{ip_address}:{port}/miner_running', timeout=self.MINER_CHECK_TIMEOUT)
            return uid, response.status_code == 200 and response.json()['status'] == 'OK'
        except Exception as e:
            self.log.info(f"Error checking uid {uid}: {e}")
            return uid, False

    def ask_miner(self, miner: MinerInfo, task: ValidatorTask) -> MinerResult:
        start_time = time.time()
        response = None
        try:
            miner_task = ContractTask(contract_code=task.contract_code)

            miner_task.sign(self.hotkey)

            task_json = miner_task.model_dump()

            result = requests.post(
                f'http://{miner.ip}:{miner.port}/forward', json=task_json, timeout=self.MINER_RESPONSE_TIMEOUT
            ).json()
            if not isinstance(result, list):
                self.log.warning(f'Got unexpected result from miner: {result}')
            else:
                response = [VulnerabilityReport(**vuln) for vuln in result]
        except Exception as e:
            self.log.info(f'Error asking miner {miner.uid} ({miner.ip}:{miner.port}): {e}')
        return MinerResult(uid=miner.uid, time=abs(time.time() - start_time), response=response)

    def ask_miners_raw(self, miners: list[MinerInfo], task: ValidatorTask) -> list[MinerResult]:
        to_check = [(x, task) for x in miners]
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.ask_miner, *args) for args in to_check]
            results = [future.result() for future in futures]
        return results

    def ask_miners_relay(self, miners: list[MinerInfo], task: ValidatorTask) -> list[MinerResult]:
        return []

    def ask_miners(self, miners: list[MinerInfo], task: ValidatorTask) -> list[MinerResult]:
        if self.mode == self.MODE_RAW:
            return self.ask_miners_raw(miners, task)
        return self.ask_miners_relay(miners, task)

    def clear_scores_for_old_hotkeys(self):
        old_hotkeys = self.hotkeys.copy()
        new_hotkeys = {uid: axon['hotkey'] for uid, axon in enumerate(self.get_axons())}
        for uid, key in old_hotkeys.items():
            if key != new_hotkeys[uid]:
                self._buffer_scores.reset(uid)
        self.hotkeys = new_hotkeys

    def validate(self):
        miners = self.get_miners()
        if not miners:
            self.log.warning('No active miners, validator would skip this loop')
            return
        task = self.try_get_task()
        if task is None:
            self.log.error('Unable to get task. Check your settings')
            raise ReinforcedError('Unable to get task')
        self.log.info(f'Validator task:\n{task}')
        responses = self.ask_miners(miners, task)

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
            self.log.info('Validator loop is running')
            sleep_time = self.get_sleep_time()
            if sleep_time:
                self.log.info(f'Validator will sleep {sleep_time} secs until next loop. Zzz...')
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
        if result is True:
            self.log.info("set_weights on chain successfully!")
        else:
            self.log.error(f"set_weights failed: {error}")

    @classmethod
    def _get_min_response_time(cls, responses: list[MinerResult]) -> float:
        """Helper method to get minimum response time from valid dendrites."""
        valid_times = [
            x.time
            for x in responses
            if x.response is not None
        ]
        return min(valid_times) if valid_times else 0.0

    @classmethod
    def _calculate_time_score(cls, result: MinerResult, min_time: float) -> float:
        """Calculate score based on response time."""
        if result.response is None or not result.time:
            return 0
        return min_time / result.time

    @classmethod
    def validate_responses(
        cls, results: list[MinerResult], task: ValidatorTask, miners: list[MinerInfo],
        log: logging.Logger = logging.getLogger('empty')
    ) -> list[float]:
        min_time = cls._get_min_response_time(results)
        scores = []
        results_by_uid = {x.uid: x for x in results}
        for miner in miners:
            result = results_by_uid[miner.uid]
            if result.response is None:
                log.debug(f'Invalid response from uid {miner.uid}')
                scores.append(0)
                continue

            report_score = cls.validate_reports_by_reference(result.response, task) * cls.WEIGHT_ONLY_SCORE
            time_score = (
                cls._calculate_time_score(result, min_time)
                * (report_score / cls.WEIGHT_ONLY_SCORE)
                * cls.WEIGHT_TIME
            )
            log.debug(f"Miner uid: {miner.uid}, hotkey: {miner.hotkey}")
            log.debug(f"Process time: {result.time}")
            log.debug(f"Report score: {report_score}, Time score: {time_score}")
            scores.append(report_score + time_score)

        log.debug(f"Final scores: {scores}")
        return scores

    def assign_achievements(
            self, rewards: list[float], miners: list[MinerInfo], achievement_count: int = 3
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
            message.sign(self.coldkey)
            result_top.append(message)
        self.log.info(f"Top miners: {result_top}")
        return result_top

    def send_top_miners(self, rewards: list[float], miners: list[MinerInfo]):
        top_miners = self.create_top_miners(rewards, miners)
        if not top_miners:
            self.log.warning('No top miners during this validation')
        result = create_session().post(
            f"{os.getenv('WEBSITE_URL')}/api/mint_medals",
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

    def save_state(self):
        self.log.info("Saving validator state.")

        state = {
            "last_validation": self._last_validation,
            "buffer_scores": self._buffer_scores.dump(),
            "hotkeys": self.hotkeys,
        }

        with open("state.pkl", "wb") as f:
            pickle.dump(state, f)

    def load_state(self):
        self.log.info("Loading validator state.")
        try:
            with open("state.pkl", "rb") as f:
                state = pickle.load(f)

            buf = ScoresBuffer(self.MAX_BUFFER)
            buf.load(state.get("buffer_scores", {}))
            self._buffer_scores = buf
            self._last_validation = state.get('last_validation', 0)
            self.hotkeys = state["hotkeys"]
        except FileNotFoundError:
            self.log.error("State file is not found.")
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
        ws_endpoint=os.getenv('CHAIN_ENDPOINT', 'wss://test.finney.opentensor.ai:443'),
        net_uid=int(os.getenv('NETWORK_UID', '222'))
    )
    validator = Validator(config)
    validator.serve_axon()
    validator.run()
