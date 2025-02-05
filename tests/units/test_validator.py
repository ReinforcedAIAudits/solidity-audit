import unittest

from ai_audits.protocol import VulnerabilityReport, ValidatorTask, TaskType
from neurons.validator import Validator

DEFAULT_FIELDS = {"from": 1, "to": 1}
DEFAULT_TASK_FIELDS = {"from": 1, "to": 1, "contractCode": "", "taskType": TaskType.LLM}


class ValidatorTestCase(unittest.TestCase):
    def test_single_vulnerability(self):
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS)],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertEqual(score, 1)
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass="Unguarded function", **DEFAULT_FIELDS)],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertEqual(score, 0)

    def test_multiple_vulnerabilities(self):
        # currently unavailable
        pass

    def test_extra_vulnerabilities(self):
        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass="Reentrancy", **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass="Outdated solidity version", **DEFAULT_FIELDS),
            ],
            ValidatorTask(vulnerabilityClass="reentrancy", **DEFAULT_TASK_FIELDS),
        )
        self.assertEqual(score, 1)

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


if __name__ == "__main__":
    unittest.main()
