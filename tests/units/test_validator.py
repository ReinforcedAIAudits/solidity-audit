import unittest

from ai_audits.protocol import VulnerabilityReport, ReferenceReport
from neurons.validator import Validator

DEFAULT_FIELDS = {'from': 1, 'to': 1, 'testCase': '', 'description': '', 'fixedLines': ''}


class ValidatorTestCase(unittest.TestCase):
    def test_single_vulnerability(self):
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass='Reentrancy', **DEFAULT_FIELDS)],
            [ReferenceReport(vulnerabilityClass=['reentrancy'], **DEFAULT_FIELDS)]
        )
        self.assertEqual(score, 1)
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass='Unguarded function', **DEFAULT_FIELDS)],
            [ReferenceReport(vulnerabilityClass=['reentrancy'], **DEFAULT_FIELDS)]
        )
        self.assertEqual(score, 0)

    def test_multiple_vulnerabilities(self):
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass='Reentrancy', **DEFAULT_FIELDS)],
            [
                ReferenceReport(vulnerabilityClass=['reentrancy'], **DEFAULT_FIELDS),
                ReferenceReport(vulnerabilityClass=['unguarded function'], **DEFAULT_FIELDS)
            ]
        )
        self.assertEqual(score, 0.5)
        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass='Unguarded function', **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass='Reentrancy', **DEFAULT_FIELDS)
            ],
            [
                ReferenceReport(vulnerabilityClass=['reentrancy'], **DEFAULT_FIELDS),
                ReferenceReport(vulnerabilityClass=['unguarded function'], **DEFAULT_FIELDS)
            ]
        )
        self.assertEqual(score, 1)
        score = Validator.validate_reports_by_reference(
            [VulnerabilityReport(vulnerabilityClass='Gas griefing', **DEFAULT_FIELDS)],
            [
                ReferenceReport(vulnerabilityClass=['reentrancy'], **DEFAULT_FIELDS),
                ReferenceReport(vulnerabilityClass=['unguarded function'], **DEFAULT_FIELDS)
            ]
        )
        self.assertEqual(score, 0)

    def test_extra_vulnerabilities(self):
        score = Validator.validate_reports_by_reference(
            [
                VulnerabilityReport(vulnerabilityClass='Reentrancy', **DEFAULT_FIELDS),
                VulnerabilityReport(vulnerabilityClass='Outdated solidity version', **DEFAULT_FIELDS)
            ],
            [ReferenceReport(vulnerabilityClass=['reentrancy'], **DEFAULT_FIELDS)]
        )
        self.assertEqual(score, 1)
