import os

from websocket import WebSocketConnectionClosedException
from template.base.miner import BaseMinerNeuron
from template.base.validator import BaseValidatorNeuron
from substrateinterface import SubstrateInterface, Keypair


__all__ = ['IdentityException', 'ReinforcedMinerNeuron', 'ReinforcedValidatorNeuron']


class IdentityException(Exception):
    pass


def set_coldkey_identity(
    substrate: SubstrateInterface, coldkey: Keypair, name: str, description: str
):
    name = name.encode('utf-8')
    description = description.encode('utf-8')
    state = substrate.query(
        module="SubtensorModule",
        storage_function="Identities",
        params=[coldkey.public_key],
    )
    if state.value["description"] == description and state.value["name"] == name:
        return
    call = substrate.compose_call(
        call_module="SubtensorModule",
        call_function="set_identity",
        call_params={
            "name": name,
            "url": b"",
            "image": b"",
            "discord": b"",
            "description": description,
            "additional": b"",
        },
    )

    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=coldkey)
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    if not receipt.is_success:
        raise IdentityException(
            f"extricsic for meta: {receipt.error_message}, \nblock number: {receipt.block_number}"
        )


def set_identity_mixin(self: BaseMinerNeuron | BaseValidatorNeuron):
    description = os.getenv("COLDKEY_DESCRIPTION")
    if not description:
        return
    try:
        set_coldkey_identity(
            self.subtensor.substrate,
            self.wallet.coldkey,
            name=self.neuron_type,
            description=description,
        )

    except (
            WebSocketConnectionClosedException,
            BrokenPipeError,
    ):
        self.subtensor.substrate.connect_websocket()


class ReinforcedMinerNeuron(BaseMinerNeuron):
    def set_identity(self):
        set_identity_mixin(self)


class ReinforcedValidatorNeuron(BaseValidatorNeuron):
    def set_identity(self):
        set_identity_mixin(self)
