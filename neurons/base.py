import os

from websocket import WebSocketConnectionClosedException
from template.base.miner import BaseMinerNeuron
from template.base.validator import BaseValidatorNeuron
from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException


class IdentityException(Exception):
    pass


def set_coldkey_identity(
    substrate: SubstrateInterface, coldkey: Keypair, name: str, description: str
):
    state = substrate.query(
        module="SubtensorModule",
        storage_function="Identities",
        params=[coldkey.public_key],
    )
    if state.value["description"] == description:
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


class ReinforcedMinerNeuron(BaseMinerNeuron):
    def set_identity(self):
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


class ReinforcedValidatorNeuron(BaseValidatorNeuron):
    pass
