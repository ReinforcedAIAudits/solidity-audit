from enum import Enum
import time
from pydantic import BaseModel, Field
from typing import Optional, Union
import json
from bittensor import Keypair as BTKeypair  # Bittensor
from substrateinterface import Keypair as SubstrateKeypair

from ai_audits.protocol import AuditsSynapse  # Substrate


KeypairType = Union[BTKeypair, SubstrateKeypair]


class SignedMessage(BaseModel):
    signature: Optional[str] = Field(
        default=None,
    )
    ss58_address: Optional[str] = Field(
        default=None,
    )

    def to_signable(self) -> bytes:
        return json.dumps(self.model_dump(exclude={"signature", "ss58_address"}), sort_keys=True).encode()

    def sign(self, keypair: KeypairType):
        self.signature = "0x" + keypair.sign(self.to_signable()).hex()
        self.ss58_address = keypair.ss58_address

    def verify(self) -> bool | Exception:
        if not self.signature or not self.ss58_address:
            return False
        try:
            vk = SubstrateKeypair(ss58_address=self.ss58_address)
            return vk.verify(signature=self.signature, data=self.to_signable())
        except Exception as e:
            return e


# Конкретное сообщение с таймстемпом
class TimestampedMessage(SignedMessage):
    timestamp: Optional[int] = Field(default=None)

    def sign(self, keypair: KeypairType):
        self.timestamp = int(time.time())
        super().sign(keypair)


class MedalRequestsMessage(TimestampedMessage):
    status: str
    medal: str
    miner_ss58_hotkey: str
    score: float


class TestMessage(TimestampedMessage):
    content: str
