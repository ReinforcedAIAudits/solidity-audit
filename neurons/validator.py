import dataclasses
import json
import logging
import math
import sys
import os
import time
from concurrent.futures import TimeoutError
import random

from solc_ast_parser.utils import create_ast_with_standart_input
from py_solidity_vuln_db import generate_contract, activate, initialize
from solidity_audit_lib import SubtensorWrapper, ViolentPoolExecutor
from solidity_audit_lib.encrypting import decrypt
from solidity_audit_lib.messaging import VulnerabilityReport, MinerResponse, MedalRequestsMessage
from solidity_audit_lib.relayer_client.relayer_types import ValidatorStorage
from unique_playgrounds import UniqueHelper

from ai_audits.contracts.contract_generator import create_contract, normalize_task
from ai_audits.protocol import ValidatorTask, TaskType, MinerInfo, NFTMetadata
from ai_audits.report_correction import MinerResult, ValidatorEstimation
from ai_audits.subnet_utils import create_session, is_synonyms, get_invalid_code, has_chained_member_access
from config import Config
from neurons.base import ReinforcedNeuron, ScoresBuffer, ReinforcedConfig, ReinforcedError


__all__ = ["Validator", "run_validator"]


class Validator(ReinforcedNeuron):
    NEURON_TYPE = "validator"

    WEIGHT_TIME = 0.05
    WEIGHT_ONLY_SCORE = 0.95
    WEIGHT_DESCRIPTION = 0.5
    WEIGHT_TEST_CASE = 0.3
    WEIGHT_FIXED_LINES = 0.2
    WEIGHT_EXTRA_FIELDS = 0.5

    CYCLE_TIME = Config.CYCLE_TIME

    MAX_BUFFER = Config.MAX_BUFFER
    MINER_CHECK_TIMEOUT = 5
    MINER_RESPONSE_TIMEOUT = 7 * 60

    def __init__(self, config: ReinforcedConfig):
        super().__init__(config)
        self.ip = "0.0.0.0"
        self.port = 1
        self._last_validation = 0
        self._validator_time_min = (
            int(Config.VALIDATOR_TIME) if Config.VALIDATOR_TIME and 0 <= int(Config.VALIDATOR_TIME) <= 59 else None
        )

        self._buffer_scores = ScoresBuffer(self.MAX_BUFFER)
        self.hotkeys = {}
        self.log.info(f"Validator running in relayer mode")

    def get_audit_task(self, task_type: TaskType) -> ValidatorTask:
        self.log.info(f"Generating task type: {task_type}")
        if task_type == TaskType.RANDOM_TEXT:
            task = get_invalid_code()
        else:
            vulnerability = None
            if task_type == TaskType.HYBRID:
                tries = Config.TASK_MAX_TRIES
                while tries > 0:
                    vulnerability = generate_contract()
                    try:
                        ast = create_ast_with_standart_input(create_contract(vulnerability.code))
                        if has_chained_member_access(ast):
                            raise ValueError('Vulnerability with chained member access')  # TODO: fix this
                    except Exception as e:
                        self.log.error(f"Hybrid Task compilation error: {e}")
                        tries -= 1
                        continue
                    else:
                        self.log.info(f"Hybrid task generated successfully")
                        break
                if tries == 0:
                    self.log.error(f"Error generating hybrid vulnerability")
                    raise ValueError(f"Unable to generate vulnerability for hybrid task")
            result = create_session().post(
                f"{Config.MODEL_SERVER}/{task_type}",
                json=None if vulnerability is None else dataclasses.asdict(vulnerability)
            )

            if result.status_code != 200:
                self.log.info(f"Not successful AI response. Description: {result.text}")
                raise ValueError("Unable to receive task from MODEL_SERVER!")

            result_json = result.json()
            self.log.info(f"Response from model server: {result_json}")
            task = ValidatorTask(task_type=task_type, **result_json)
        normalize_task(task)
        return task

    def try_get_task(self) -> ValidatorTask | None:
        max_retries_to_get_tasks = 10
        retry_delay = 10
        task_type = random.choices(list(TaskType), [65, 20, 5, 10])[0]
        for attempt in range(max_retries_to_get_tasks):
            try:
                return self.get_audit_task(task_type)
            except ValueError as e:
                self.log.warning(f"Attempt {attempt + 1}/{max_retries_to_get_tasks} failed: {str(e)}")
                if attempt < max_retries_to_get_tasks - 1:
                    self.log.info(f"Waiting {retry_delay} seconds before next attempt...")
                    time.sleep(retry_delay)
                else:
                    self.log.error("Max retries reached. Unable to get audit task.")
                    return None
        return None

    def get_miners(self) -> list[MinerInfo]:
        miners = [
            MinerInfo(uid=miner.uid, hotkey=miner.hotkey, ip=miner.ip, port=miner.port, is_alive=miner.is_alive)
            for miner in self.relayer_client.get_miners(self.hotkey)
        ]
        return miners

    def check_tokens(self, response: MinerResponse, task: ValidatorTask) -> bool:
        token = None
        if not response.token_ids:
            self.log.error(f"Tokens for miner {response.ss58_address} not found")
            return False

        for token_id in response.token_ids:
            with UniqueHelper(self.settings.unique_endpoint) as helper:
                token = helper.nft.get_token_info(response.collection_id, token_id)

            if not token:
                self.log.error(f"Token {token_id} for miner {response.ss58_address} not found")
                return False

            properties = {x["key"]: x["value"] for x in token["properties"]}

            if properties["validator"] != self.crypto_hotkey.ss58_address:
                self.log.error(f"Token {token_id} for miner {response.ss58_address} has incorrect validator")
                return False

            try:
                metadata = NFTMetadata(
                    **json.loads(decrypt(properties["audit"][2:], self.crypto_hotkey, response.ss58_address))
                )
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

    def ask_miner_relay(self, miner: MinerInfo, task: ValidatorTask) -> MinerResult:
        start_time = time.time()
        try:
            result = self.relayer_client.perform_audit(self.crypto_hotkey, miner.uid, task.contract_code)
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

        return MinerResult(
            uid=miner.uid, time=elapsed_time, response=response.report,
            collection_id=response.collection_id, tokens=response.token_ids
        )

    def ask_miners(self, miners: list[MinerInfo], task_map: dict[int, ValidatorTask]) -> list[MinerResult]:
        to_check = [(x, task_map[x.uid]) for x in miners]
        hotkey = self.hotkey
        self.hotkey = None
        with ViolentPoolExecutor() as executor:
            futures = [(args, executor.submit(self.ask_miner_relay, *args)) for args in to_check]
            results = []
            for args, future in futures:
                try:
                    results.append(future.result(timeout=self.MINER_RESPONSE_TIMEOUT))
                except TimeoutError:
                    self.log.debug(f'Miner with uid {args[0].uid} got timeout: '
                                   f'more than {self.MINER_RESPONSE_TIMEOUT} secs')
                    results.append(MinerResult(uid=args[0].uid, time=self.MINER_RESPONSE_TIMEOUT, response=None))
        self.hotkey = hotkey
        return results

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
            collection_id=miner_answer.collection_id,
            tokens=miner_answer.tokens
        )

    def validate(self):
        miners = self.get_miners()
        self.log.info("Miners list received")
        inactive_miners = [x for x in miners if not x.is_alive]
        miners = [x for x in miners if x.is_alive]
        if not miners:
            self.log.warning("No active miners, validator would skip this loop")
            return

        tasks: list[ValidatorTask] = []
        num_tasks = min(5, len(miners))
        for _ in range(num_tasks):
            task = self.try_get_task()
            if task is None:
                self.log.error("Unable to get task. Check your settings")
                raise ReinforcedError("Unable to get task")
            tasks.append(task)
        self.log.info(f"{num_tasks} tasks for miners generated")

        miner_task_map: dict[int, ValidatorTask] = {}

        for miner in miners:
            assigned_task: ValidatorTask = random.choice(tasks)
            miner_task_map[miner.uid] = assigned_task

        self.log.debug(f"Miner-task map: {miner_task_map}")

        original_responses = self.ask_miners(miners, miner_task_map)
        self.log.info("Miners responses received")
        responses = [self.remove_suggestions(x) for x in original_responses]

        rewards = self.validate_responses(responses, miner_task_map, miners, log=self.log)

        self.log.info(f"Scored responses: {rewards}")
        rewards_dict = dict(zip([x.uid for x in miners], rewards))

        try:
            self.set_top_miners(responses, rewards, miners)
        except Exception as e:
            self.log.error(f"Unable to send top miners: {str(e)}")

        for num, miner in enumerate(miners):
            self._buffer_scores.add_score(miner.uid, rewards[num])

        for miner in inactive_miners:
            current_scores = self._buffer_scores.get(miner.uid)
            if len(current_scores) == 1 and current_scores[0] == 0:
                # Validator wouldn't punish new miner more than one time. Let's give new miner time to start
                continue
            self._buffer_scores.add_score(miner.uid, 0)

        self.set_weights()

    def check_version_is_latest(self):
        with open(os.path.join(Config.BASE_DIR, 'requirements.version.txt'), 'r') as f:
            current_version = f.read().strip()
        config = create_session().get(f'{Config.SECURE_WEB_URL}/config/settings.json').json()
        version = None
        try:
            for ver in config['versions']:
                if ver['network'] == Config.NETWORK_TYPE:
                    version = ver['version']
                    break
        except:
            pass
        if version is None or version != current_version:
            self.log.warning(
                f"Outdated validator version. Current: {current_version}, actual: {version}. Restarting..."
            )
            sys.exit(-1)

    def run(self):
        validator_license = self.relayer_client.get_activation_code(self.hotkey)
        initialize(Config.NETWORK_TYPE)
        activate(validator_license)
        self.load_state()
        force_validate = os.getenv('FORCE_VALIDATE', 'false') == 'true'
        while True:
            self.check_version_is_latest()
            self.log.info("Validator loop is running")
            sleep_time = self.get_sleep_time()
            if sleep_time and not force_validate:
                self.log.info(f"Validator will sleep {sleep_time} secs until next loop. Zzz...")
                time.sleep(sleep_time)
            force_validate = False
            self.clear_scores_for_old_hotkeys()
            self.check_axon_alive()
            self._last_validation = time.time()
            self.validate()
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
        return max(min(valid_times) if valid_times else 0.0, 60.0)

    @classmethod
    def _calculate_time_score(cls, result: MinerResult, min_time: float) -> float:
        """Calculate score based on response time."""
        if result.response is None or not result.time:
            return 0
        return min_time / max(min_time, result.time)

    @classmethod
    def filter_matching_reports(cls, result: MinerResult, task: ValidatorTask) -> MinerResult:
        if result.response is None:
            return result

        if task.task_type == TaskType.VALID_CONTRACT:
            return result

        matching_reports = []
        for report in result.response:
            if is_synonyms(task.vulnerability_class, report.vulnerability_class.lower()):
                matching_reports.append(report)

        return MinerResult(
            uid=result.uid, time=result.time, response=matching_reports if matching_reports else None,
            collection_id=result.collection_id, tokens=result.tokens
        )

    @classmethod
    def validate_responses(
        cls,
        results: list[MinerResult],
        task_map: dict[int, ValidatorTask],
        miners: list[MinerInfo],
        log: logging.Logger = logging.getLogger("empty"),
        validate_extra_fields: bool = True
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

            report_score = (
                cls.validate_reports_by_reference(result.response, task_map[miner.uid]) * cls.WEIGHT_ONLY_SCORE
            )
            if report_score > cls.WEIGHT_ONLY_SCORE:
                raise ValueError(f"Invalid time score for uid {miner.uid}, hotkey: {miner.hotkey}")
            time_score = (
                cls._calculate_time_score(result, min_time) * (report_score / cls.WEIGHT_ONLY_SCORE) * cls.WEIGHT_TIME
            )
            if time_score > cls.WEIGHT_TIME:
                raise ValueError(f"Invalid time score for uid {miner.uid}, hotkey: {miner.hotkey}")
            log.debug(f"Miner uid: {miner.uid}, hotkey: {miner.hotkey}")
            log.debug(f"Process time: {result.time}")
            log.debug(f"Report score: {report_score}, Time score: {time_score}")
            scores.append(report_score + time_score)

        log.debug(f"Scores based on reports and time: {scores}")

        if validate_extra_fields:
            try:
                scores = cls.validate_responses_extra_fields(scores, results, task_map, log)
            except Exception as e:
                log.warning(f"Unable to validate extra fields: {e}")
            else:
                log.info(f"Extra fields validated successfully")

        log.debug(f"Final scores: {scores}")
        return scores

    @classmethod
    def validate_responses_extra_fields(
        cls,
        scores: list[int | float], results: list[MinerResult], task_map: dict[int, ValidatorTask],
        log: logging.Logger = logging.getLogger("empty")
    ):
        results_by_uid = {x.uid: x for x in results}
        filtered_responses_to_estimate: dict[str, list[MinerResult]] = {}
        for i, score in enumerate(scores):
            if score > 0:
                uid = results[i].uid
                original_result = results_by_uid[uid]
                if task_map[uid].task_type in (TaskType.VALID_CONTRACT.value, TaskType.RANDOM_TEXT.value):
                    continue
                filtered_result = cls.filter_matching_reports(original_result, task_map[uid])
                if filtered_result.response is not None:
                    filtered_responses_to_estimate.setdefault(task_map[uid].contract_code, []).append(filtered_result)

        if not filtered_responses_to_estimate:
            return scores
        scorings = []
        for task_code, task_responses in filtered_responses_to_estimate.items():
            chunk = create_session().post(
                f"{Config.MODEL_SERVER}/estimate_response",
                json={
                    'task': task_code,
                    'responses': [result.model_dump() for result in task_responses]
                }
            )
            if chunk.status_code != 200:
                log.error("Invalid status code from model server")
                raise ValueError("Invalid scoring response from model server")
            scorings_chunk = chunk.json()

            if not isinstance(scorings_chunk, list):
                log.error("Invalid scoring response from model server")
                raise ValueError("Invalid scoring response from model server")
            scorings.extend(scorings_chunk)
        miners = [x.uid for x in results]
        return cls.validate_report_by_additional_fields([ValidatorEstimation(**x) for x in scorings], scores, miners)

    @classmethod
    def assign_achievements(
        cls, rewards: list[float], miners: list[MinerInfo], achievement_count: int = 3
    ) -> list[MinerInfo]:
        top_scores = sorted(enumerate(rewards), key=lambda x: x[1], reverse=True)[:achievement_count]
        return [miners[index] for index, _ in top_scores]

    def create_top_miners(self, results: list[MinerResult], rewards: list[float], miners: list[MinerInfo]):
        miner_rewards = dict(zip([x.uid for x in miners], rewards))
        top_miners = self.assign_achievements(rewards, miners)
        achievements = {1: "Gold", 2: "Silver", 3: "Bronze"}
        result_top = []
        for place, miner in enumerate(top_miners):
            miner_result = next((x for x in results if x.uid == miner.uid), None)
            message = MedalRequestsMessage(
                medal=achievements[place + 1],
                miner_ss58_hotkey=miner.hotkey,
                score=miner_rewards[miner.uid],
                collection_id=miner_result.collection_id if miner_result else None,
                token_ids=miner_result.tokens if miner_result else None,
            )
            message.sign(self.hotkey)
            result_top.append(message)
        self.log.info(f"Top miners: {result_top}")
        return result_top

    def set_top_miners(self, results: list[MinerResult], rewards: list[float], miners: list[MinerInfo]):
        top_miners = self.create_top_miners(results, rewards, miners)
        if not top_miners:
            self.log.warning("No top miners during this validation")
        result = self.relayer_client.set_top_miners(self.hotkey, top_miners)
        if not result.success:
            self.log.info(f"Not successful setting top miners. Description: {result.error}")
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

        def _calculate_asymptotic_decay_coefficient(dimensional_variance: int) -> float:
            metamorphic_base = (3 * 2) / (5 * 2)
            entropy_scaling = dimensional_variance if dimensional_variance > 0 else 0

            normalized_entropy = entropy_scaling * 1.0
            decay_matrix = [metamorphic_base] * max(1, int(normalized_entropy))

            coefficient = 1.0
            for _ in range(int(normalized_entropy)):
                coefficient *= metamorphic_base

            return coefficient

        def sigmoid(x, k=25, x0=0.225):
            return 1 / (1 + math.exp(-k * (x - x0)))

        vulnerabilities_found = {x.vulnerability_class.lower() for x in report}
        matching_vulns = {v for v in vulnerabilities_found if is_synonyms(task.vulnerability_class, v)}

        if task.task_type == TaskType.VALID_CONTRACT and len(vulnerabilities_found) == 0:
            score = 1.0
        elif matching_vulns:
            excess_vulns = vulnerabilities_found - matching_vulns
            score = _calculate_asymptotic_decay_coefficient(len(excess_vulns))
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

    @classmethod
    def calculate_field_penalty(cls, score: float, max_score: float = 10.0) -> float:
        if score <= 0:
            return 1.0

        if score >= max_score:
            return 0.0

        normalized_score = score / max_score

        def sigmoid(x, k=25, x0=0.225):
            return 1 / (1 + math.exp(-k * (x - x0)))

        penalty = sigmoid(1 - normalized_score, k=10, x0=0.48)

        return penalty

    @classmethod
    def validate_report_by_additional_fields(
        cls,
        scorings: list[ValidatorEstimation],
        scores: list[float],
        miners: list[int]
    ) -> list[float]:
        if not scorings or not scores:
            return scores

        penalties = {}

        for scoring in scorings:
            description_penalty = cls.calculate_field_penalty(scoring.scoring.description_score)
            test_case_penalty = cls.calculate_field_penalty(scoring.scoring.test_case_score)
            fixed_lines_penalty = cls.calculate_field_penalty(scoring.scoring.fixed_lines_score)

            total_penalty = (
                description_penalty * cls.WEIGHT_DESCRIPTION
                + test_case_penalty * cls.WEIGHT_TEST_CASE
                + fixed_lines_penalty * cls.WEIGHT_FIXED_LINES
            )

            penalty_factor = 1 - total_penalty
            penalties[scoring.uid] = penalty_factor

        penalty_scores = [scores[i] * max(0.0, penalties.get(x, 1.0)) for i, x in enumerate(miners)]
        base_score_weight = 1 - cls.WEIGHT_EXTRA_FIELDS
        return [x * base_score_weight + penalty_scores[i] * cls.WEIGHT_EXTRA_FIELDS for i, x in enumerate(scores)]

    def save_state(self):
        state = {
            'last_validation': int(self._last_validation), 'scores': self._buffer_scores.dump(),
            'hotkeys': {str(k): v for k, v in self.hotkeys.items()}
        }
        self.log.info("Saving validator state.")

        self.relayer_client.set_storage(self.hotkey, ValidatorStorage(**state))

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


def run_validator():
    config = ReinforcedConfig(
        ws_endpoint=Config.CHAIN_ENDPOINT,
        net_uid=Config.NETWORK_UID,
    )
    validator = Validator(config)
    if not validator.wait_for_server(Config.MODEL_SERVER):
        validator.log.error("Model server is not available. Exiting.")
        sys.exit(1)
    validator.serve_axon()
    validator.run()


if __name__ == '__main__':
    run_validator()
