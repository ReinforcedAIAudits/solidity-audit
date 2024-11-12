import os
import random
from typing import List

from websocket import WebSocketConnectionClosedException
from template.base.miner import BaseMinerNeuron
from template.base.validator import BaseValidatorNeuron
from substrateinterface import SubstrateInterface, Keypair

from template.utils.uids import check_uid_availability


__all__ = ["IdentityException", "ReinforcedMinerNeuron", "ReinforcedValidatorNeuron"]


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
    if (
        state.value is not None
        and state.value["description"] == description
        and state.value["name"] == name
    ):
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

def get_random_uids(self, k: int, exclude: List[int] = None) -> list:
    """Returns k available random uids from the metagraph.
    Args:
        k (int): Number of uids to return.
        exclude (List[int]): List of uids to exclude from the random sampling.
    Returns:
        uids (np.ndarray): Randomly sampled available uids.
    Notes:
        If `k` is larger than the number of available `uids`, set `k` to the number of available `uids`.
    """
    exclude = set(exclude) if exclude else set()
    
    candidate_uids = [
        uid
        for uid in range(self.metagraph.n.item())
        if check_uid_availability(
            self.metagraph, uid, self.config.neuron.vpermit_tao_limit
        )
        and uid not in exclude
    ]

    k = min(k, len(candidate_uids))

    uids = random.sample(candidate_uids, k)

    return uids

class ReinforcedMinerNeuron(BaseMinerNeuron):
    def set_identity(self):
        set_identity_mixin(self)


class ReinforcedValidatorNeuron(BaseValidatorNeuron):
    def set_identity(self):
        set_identity_mixin(self)
