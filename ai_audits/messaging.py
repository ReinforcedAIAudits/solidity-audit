import json

from bittensor import Keypair as BTKeypair  # Bittensor
from async_substrate_interface.sync_substrate import Keypair as SubstrateKeypair
from pydantic import BaseModel, Field


__all__ = ['KeypairType', 'sign', 'verify', 'SignedMessage']


KeypairType = BTKeypair | SubstrateKeypair


def sign(data: bytes, keypair: KeypairType) -> tuple[str, str]:
    return "0x" + keypair.sign(data).hex(), keypair.ss58_address


def verify(data: bytes, signature: str, ss58_address: str) -> bool | Exception:
    if not signature or not ss58_address:
        return False
    try:
        vk = SubstrateKeypair(ss58_address=ss58_address)
        return vk.verify(signature=signature, data=data)
    except Exception as e:
        return e


class SignedMessage(BaseModel):
    signature: str | None = Field(
        default=None,
    )
    ss58_address: str | None = Field(
        default=None,
    )

    def to_signable(self) -> bytes:
        return json.dumps(self.model_dump(exclude={"signature", "ss58_address"}), sort_keys=True).encode()

    def sign(self, keypair: KeypairType):
        self.signature, self.ss58_address = sign(self.to_signable(), keypair)

    def verify(self) -> bool | Exception:
        return verify(self.to_signable(), self.signature, self.ss58_address)
