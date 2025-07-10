import unittest
from ai_audits.nft_protocol import TestMessage
from bittensor import Keypair as BTKeypair
from hypothesis import given, strategies as st


class TestNFTProtocol(unittest.TestCase):

    def setUp(self):
        self.keypair = BTKeypair.create_from_mnemonic(BTKeypair.generate_mnemonic())

    def test_sign_and_verify(self):
        message = TestMessage(content="Hello, world!")
        message.sign(self.keypair)
        self.assertTrue(message.verify())

    def test_verify_without_signature(self):
        message = TestMessage(content="Hello, world!")
        self.assertFalse(message.verify())

    def test_verify_with_invalid_signature(self):
        message = TestMessage(content="Hello, world!")
        message.sign(self.keypair)
        message.ss58_address = BTKeypair.create_from_mnemonic(BTKeypair.generate_mnemonic()).ss58_address

        self.assertFalse(message.verify())

    @given(st.text())
    def test_sign_and_verify_with_hypothesis(self, content):
        message = TestMessage(content=content)
        message.sign(self.keypair)
        self.assertTrue(message.verify())


if __name__ == "__main__":
    unittest.main()
