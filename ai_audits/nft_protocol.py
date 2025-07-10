import time

from pydantic import Field
from solidity_audit_lib.messaging import SignedMessage, KeypairType

__all__ = ["TimestampedMessage", "MedalRequestsMessage"]


class TimestampedMessage(SignedMessage):
    timestamp: int | None = Field(default=None)

    def sign(self, keypair: KeypairType):
        self.timestamp = int(time.time())
        super().sign(keypair)


class MedalRequestsMessage(TimestampedMessage):
    medal: str
    miner_ss58_hotkey: str
    score: float


class TestMessage(TimestampedMessage):
    content: str
