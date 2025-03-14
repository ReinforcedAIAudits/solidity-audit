from enum import Enum
import time
from pydantic import BaseModel, Field
from typing import List, Optional, Tuple, Union
import json
from bittensor import Keypair as BTKeypair  # Bittensor
from substrateinterface import Keypair as SubstrateKeypair

from ai_audits.protocol import AuditsSynapse, VulnerabilityReport  # Substrate

KeypairType = Union[BTKeypair, SubstrateKeypair]


def sign(data: str, keypair: KeypairType) -> Tuple[str, str]:
    return "0x" + keypair.sign(data).hex(), keypair.ss58_address


def verify(data: str, signature: str, ss58_address: str) -> bool | Exception:
    if not signature or not ss58_address:
        return False
    try:
        vk = SubstrateKeypair(ss58_address=ss58_address)
        return vk.verify(signature=signature, data=data)
    except Exception as e:
        return e


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
        self.signature, self.ss58_address = sign(self.to_signable(), keypair)

    def verify(self) -> bool | Exception:
        return verify(self.to_signable(), self.signature, self.ss58_address)


class TimestampedMessage(SignedMessage):
    timestamp: Optional[int] = Field(default=None)

    def sign(self, keypair: KeypairType):
        self.timestamp = int(time.time())
        super().sign(keypair)


class MedalRequestsMessage(TimestampedMessage):
    medal: str
    miner_ss58_hotkey: str
    score: float


class ContractTask(SignedMessage):
    contract_code: str


class ReportMessage(SignedMessage):
    report: List[VulnerabilityReport]


class TestMessage(TimestampedMessage):
    content: str
