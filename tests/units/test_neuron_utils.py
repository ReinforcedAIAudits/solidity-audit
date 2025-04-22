import unittest

from neurons.base import ScoresBuffer


__all__ = ['NeuronUtilsTestCase']


class NeuronUtilsTestCase(unittest.TestCase):
    def test_scores_buffer(self):
        buff = ScoresBuffer(3)
        buff.add_score(1, 0.9)
        self.assertEqual(buff.dump(), {'1': [0.9]})
        buff.load({'2': [0.5, 0.6, 0.7, 0.8]})
        self.assertEqual(buff.dump(), {'2': [0.6, 0.7, 0.8]})
        with self.assertRaises(KeyError):
            buff.add_score('2', 0.9)
        with self.assertRaises(ValueError):
            buff.add_score(2, '0.9')
        buff.add_score(2, 0.9)
        self.assertEqual(buff.dump(), {'2': [0.7, 0.8, 0.9]})
        with self.assertRaises(ValueError):
            buff.add_score(2, 1.1)
        with self.assertRaises(ValueError):
            buff[1] = [1, 1.1]
        buff[1] = [1, 1]
        self.assertEqual(buff.dump(), {'2': [0.7, 0.8, 0.9], '1': [1, 1]})
        self.assertEqual(buff.uids(), [2, 1])
        self.assertEqual(buff.scores(), [52428, 65535])
