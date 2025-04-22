import unittest

from solidity_audit_lib.messaging import VulnerabilityReport

from ai_audits.protocol import ValidatorTask, TaskType, MinerInfo
from neurons.validator import Validator, MinerResult

DEFAULT_FIELDS = {"from": 1, "to": 1}
DEFAULT_TASK_FIELDS = {"from": 1, "to": 1, "contractCode": "", "taskType": TaskType.LLM}


class ValidatorTestCase(unittest.TestCase):
    def test_single_vulnerability(self):
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertLessEqual(1 - score, 0.0015)
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass="Unguarded function", **DEFAULT_FIELDS)],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertEqual(score, 0)

    def test_multiple_vulnerabilities(self):
        # currently unavailable
        pass

    def test_extra_vulnerabilities(self):
        perfectly_matched_score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS),
            ],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertLessEqual(1 - perfectly_matched_score, 0.0015)

        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Outdated solidity version", **DEFAULT_FIELDS),
            ],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertLessEqual(1 - score, 0.05)

        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Outdated solidity version", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass", **DEFAULT_FIELDS),
            ],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertLessEqual(abs(0.8 - score), 0.025)

        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Outdated solidity version", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#1", **DEFAULT_FIELDS),
            ],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertEqual(score, 0.5)

        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Outdated solidity version", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#1", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#2", **DEFAULT_FIELDS),
            ],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertLessEqual(score, 0.35)

        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Outdated solidity version", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#1", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#2", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#3", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#4", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#5", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#6", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Missclass#7", **DEFAULT_FIELDS),
            ],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertLessEqual(score, 0.1)

    def test_hybrid_scoring(self):
        # Healthy code: 20 lines, Vulnerable code: 5 lines
        healthy_code = "\n".join([f"line {i}" for i in range(1, 21)])
        vulnerable_code = "\n".join([f"vuln line {i}" for i in range(21, 26)])
        full_code = healthy_code + "\n" + vulnerable_code

        # Exact match for vulnerable lines
        exact_vulnerability_report = VulnerabilityReport(
            vulnerabilityClass="Reentrancy", from_line=21, to_line=25, contractCode=full_code
        )

        # Approximate match with 12 lines (5 vulnerable + 7 healthy)
        approximate_vulnerability_report = VulnerabilityReport(
            vulnerabilityClass="Reentrancy", from_line=13, to_line=25, contractCode=full_code
        )

        # Validator task
        validator_task = ValidatorTask(
            vulnerabilityClass="reentrancy", from_line=21, to_line=25, contractCode=full_code, taskType=TaskType.HYBRID
        )

        # Exact match should score 1
        score = Validator.validate_reports_by_reference([exact_vulnerability_report], validator_task)
        self.assertLess(1 - score, 0.01)

        # Approximate match should score less than 1 but more than 0
        score = Validator.validate_reports_by_reference([approximate_vulnerability_report], validator_task)
        print(score)
        self.assertGreater(score, 0)
        self.assertLess(score, 1)

    def test_validate_responses(self):
        miners = [
            MinerInfo(uid=0, ip='0.0.0.0', port=8090, hotkey='hotkey0'),
            MinerInfo(uid=1, ip='0.0.0.0', port=8091, hotkey='hotkey1'),
            MinerInfo(uid=2, ip='0.0.0.0', port=8092, hotkey='hotkey2'),
        ]
        responses = [
            MinerResult(
                uid=0, time=1,
                response=[VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)]
            ),
            MinerResult(
                uid=1, time=2,
                response=[VulnerabilityReport(vulnerabilityClass="Outdated solidity version", **DEFAULT_FIELDS)]
            ),
            MinerResult(
                uid=2, time=0.5,
                response=[VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)]
            )
        ]

        task = ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS)

        scores = Validator.validate_responses(responses, task, miners)

        self.assertEqual(len(scores), 3)
        self.assertGreater(scores[0], scores[1])
        self.assertGreater(scores[2], scores[0])

        self.assertLessEqual(1 - scores[0], 0.06)
        self.assertEqual(scores[1], 0)
        self.assertLessEqual(1 - scores[2], 0.0015)

    def test_validate_responses_with_no_responses(self):
        responses = []
        task = ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS)

        scores = Validator.validate_responses(responses, task, [])

        self.assertEqual(scores, [])

    def test_validate_responses_with_no_success_responses(self):
        miners = [
            MinerInfo(uid=0, ip='0.0.0.0', port=8090, hotkey='hotkey0'),
            MinerInfo(uid=1, ip='0.0.0.0', port=8091, hotkey='hotkey1')
        ]
        responses = [
            MinerResult(
                uid=0, time=1,
                response=[VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)]
            ),
            MinerResult(
                uid=1, time=2,
                response=[VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)]
            )
        ]

        task = ValidatorTask(vulnerabilityClass="integer overflow", **DEFAULT_TASK_FIELDS)

        scores = Validator.validate_responses(responses, task, miners)

        self.assertEqual(scores, [0.0, 0.0])

    def test_validate_responses_with_same_time(self):
        miners = [
            MinerInfo(uid=0, ip='0.0.0.0', port=8090, hotkey='hotkey0'),
            MinerInfo(uid=1, ip='0.0.0.0', port=8091, hotkey='hotkey1')
        ]
        responses = [
            MinerResult(
                uid=0, time=1,
                response=[VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)]
            ),
            MinerResult(
                uid=1, time=1,
                response=[VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)]
            )
        ]

        task = ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS)

        scores = Validator.validate_responses(responses, task, miners)

        self.assertEqual(len(scores), 2)
        self.assertEqual(scores[0], scores[1])
        self.assertLessEqual(1 - scores[0], 0.0015)

    def test_validate_responses_with_multiple_reports(self):
        miners = [
            MinerInfo(uid=0, ip='0.0.0.0', port=8090, hotkey='hotkey0'),
            MinerInfo(uid=1, ip='0.0.0.0', port=8091, hotkey='hotkey1')
        ]
        responses = [
            MinerResult(
                uid=0, time=1,
                response=[
                    VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS),
                    VulnerabilityReport(vulnerabilityClass="Outdated solidity version", **DEFAULT_FIELDS),
                ]
            ),
            MinerResult(
                uid=1, time=1,
                response=[VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)]
            )
        ]

        task = ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS)

        scores = Validator.validate_responses(responses, task, miners)

        self.assertEqual(len(scores), 2)
        self.assertLessEqual(1 - scores[0], 0.05)  # Multiple reports should have slightly lower score
        self.assertLessEqual(1 - scores[1], 0.0015)  # Single correct report should have high score


if __name__ == "__main__":
    unittest.main()
