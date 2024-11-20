import unittest

from ai_audits.protocol import VulnerabilityReport, ValidatorTask
from neurons.validator import Validator

DEFAULT_FIELDS = {'from': 1, 'to': 1, 'testCase': '', 'description': '', 'fixedLines': ''}
DEFAULT_TASK_FIELDS = {'from': 1, 'to': 1, 'contractCode': ''}


class ValidatorTestCase(unittest.TestCase):
    def test_single_vulnerability(self):
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass='Reentrancy', **DEFAULT_FIELDS)],
            ValidatorTask(vulnerabilityClass='reentrancy', **DEFAULT_TASK_FIELDS)
        )
        self.assertEqual(score, 1)
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass='Unguarded function', **DEFAULT_FIELDS)],
            ValidatorTask(vulnerabilityClass='reentrancy', **DEFAULT_TASK_FIELDS)
        )
        self.assertEqual(score, 0)

    def test_multiple_vulnerabilities(self):
        # currently unavailable
        pass

    def test_extra_vulnerabilities(self):
        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass='Reentrancy', **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass='Outdated solidity version', **DEFAULT_FIELDS)
            ],
            ValidatorTask(vulnerabilityClass='reentrancy', **DEFAULT_TASK_FIELDS)
        )
        self.assertEqual(score, 1)
