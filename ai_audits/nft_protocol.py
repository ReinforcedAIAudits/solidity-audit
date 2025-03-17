import time
from pydantic import Field
from typing import Optional

from ai_audits.mesaging import SignedMessage, KeypairType


__all__ = ["TimestampedMessage", "MedalRequestsMessage"]


class TimestampedMessage(SignedMessage):
    timestamp: Optional[int] = Field(default=None)

    def sign(self, keypair: KeypairType):
        self.timestamp = int(time.time())
        super().sign(keypair)


class MedalRequestsMessage(TimestampedMessage):
    medal: str
    miner_ss58_hotkey: str
    score: float


class TestMessage(TimestampedMessage):
    content: str
