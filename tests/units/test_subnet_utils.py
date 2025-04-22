import unittest

from ai_audits.subnet_utils import is_synonyms


__all__ = ['SubnetUtilsTestCase']


class SubnetUtilsTestCase(unittest.TestCase):
    def test_compare_synonyms(self):
        self.assertTrue(is_synonyms('Unguarded function', 'Unexpected privilege grants'))
        self.assertTrue(is_synonyms('Unguarded function', 'unguarded function'))
        self.assertTrue(is_synonyms('Gas griefing', 'Gas grief'))
        self.assertTrue(is_synonyms('Race condition', 'Race condition'))
        self.assertFalse(is_synonyms('Unguarded function', 'bad randomness'))

