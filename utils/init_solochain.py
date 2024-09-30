import time
from typing import List, Tuple
import bittensor
from bittensor_cli import CLIManager
from substrateinterface import SubstrateInterface, Keypair
from websocket import WebSocketBadStatusException, WebSocketConnectionClosedException

# Constants
OWNER_NAME = "owner"
VALIDATOR_NAME = "validator"
MINER_NAME = "miner"
ROOT_ID = 0
NET_UID = 1
SUBNET_TEMPO = 10
EMISSION_TEMPO = 30
NETWORK_TYPE = "local"
NETWORK_URL = "ws://localhost:9946"

# Initialize Subtensor and Substrate Interface
subtensor = bittensor.subtensor(network=NETWORK_URL)
substrate = SubstrateInterface(url=NETWORK_URL)

# Keypairs
keypair_alice = Keypair.create_from_uri("//Alice")


# CLI Manager
btcli = CLIManager()
btcli.main_callback()


def create_extrinsic(
    pallet: str, method: str, params: dict, keypair: Keypair = keypair_alice
):
    return substrate.create_signed_extrinsic(
        call=substrate.compose_call(
            call_module=pallet, call_function=method, call_params=params
        ),
        keypair=keypair,
    )


def create_sudo_extrinsic(
    pallet: str, method: str, params: dict, keypair: Keypair = keypair_alice
):
    return substrate.create_signed_extrinsic(
        call=substrate.compose_call(
            call_module="Sudo",
            call_function="sudo",
            call_params={
                "call": substrate.compose_call(
                    call_module=pallet, call_function=method, call_params=params
                ).value
            },
        ),
        keypair=keypair,
    )


def submit_sudo_extrinsic(method: str, params: dict):
    try:
        receipt = substrate.submit_extrinsic(
            create_sudo_extrinsic("AdminUtils", method, params),
            wait_for_finalization=True,
            wait_for_inclusion=True,
        )
        if not receipt.is_success:
            raise ValueError(
                f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
            )
    except (
        WebSocketConnectionClosedException,
        BrokenPipeError,
    ):
        substrate.connect_websocket()


def setup_wallet(uri: str) -> Tuple[bittensor.Keypair, bittensor.wallet]:
    keypair = bittensor.Keypair.create_from_uri(uri)
    wallet_path = f"/tmp/btcli-wallet-{uri.strip('/')}"
    wallet = bittensor.wallet(path=wallet_path)

    wallet.set_coldkey(keypair=keypair, encrypt=False, overwrite=True)
    wallet.set_coldkeypub(keypair=keypair, encrypt=False, overwrite=True)
    wallet.set_hotkey(keypair=keypair, encrypt=False, overwrite=True)

    return keypair, wallet


def create_wallet(name: str):
    btcli.wallet_create_wallet(
        wallet_name=name,
        wallet_hotkey="default",
        use_password=False,
        quiet=False,
        wallet_path="~/.bittensor/wallets",
        n_words=21,
    )


def transfer_funds_if_needed(wallet: bittensor.wallet, alice_wallet: bittensor.wallet):
    if subtensor.get_balance(wallet.coldkey.ss58_address).tao < 10000.0:
        btcli.wallet_transfer(
            destination_ss58_address=wallet.coldkey.ss58_address,
            amount=15000,
            wallet_name=alice_wallet.name,
            wallet_hotkey=alice_wallet.hotkey_str,
            wallet_path=alice_wallet.path,
            quiet=False,
            network=NETWORK_TYPE,
            chain=NETWORK_URL,
        )


def init():
    _, alice_wallet = setup_wallet("//Alice")

    for name in [OWNER_NAME, VALIDATOR_NAME, MINER_NAME]:
        create_wallet(name)
        wallet = bittensor.wallet(name, "default")
        transfer_funds_if_needed(wallet, alice_wallet)

    # Get wallets
    owner_wallet = bittensor.wallet(OWNER_NAME, "default")
    validator_wallet = bittensor.wallet(VALIDATOR_NAME, "default")
    miner_wallet = bittensor.wallet(MINER_NAME, "default")

    # Register commands

    btcli.subnets_create(
        wallet_name=owner_wallet.name,
        wallet_hotkey=owner_wallet.hotkey_str,
        wallet_path=owner_wallet.path,
        quiet=False,
    )

    btcli.root_register(
        wallet_name=validator_wallet.name,
        wallet_hotkey=validator_wallet.hotkey_str,
        wallet_path=validator_wallet.path,
        quiet=False,
    )

    for wallet in [validator_wallet, miner_wallet]:
        btcli.subnets_register(
            netuid=NET_UID,
            wallet_name=wallet.name,
            wallet_path=wallet.path,
            wallet_hotkey=wallet.hotkey_str,
            quiet=False,
        )
        time.sleep(5)

    # Set various limits and tempos
    submit_sudo_extrinsic(
        "sudo_set_weights_set_rate_limit",
        {"netuid": NET_UID, "weights_set_rate_limit": 0},
    )
    submit_sudo_extrinsic(
        "sudo_set_weights_set_rate_limit",
        {"netuid": ROOT_ID, "weights_set_rate_limit": 0},
    )
    submit_sudo_extrinsic(
        "sudo_set_target_stakes_per_interval", {"target_stakes_per_interval": 1000}
    )
    submit_sudo_extrinsic(
        "sudo_set_target_registrations_per_interval",
        {"netuid": NET_UID, "target_registrations_per_interval": 1000},
    )
    submit_sudo_extrinsic("sudo_set_tx_rate_limit", {"tx_rate_limit": 0})
    submit_sudo_extrinsic("sudo_set_tempo", {"netuid": NET_UID, "tempo": SUBNET_TEMPO})
    submit_sudo_extrinsic("sudo_set_tempo", {"netuid": ROOT_ID, "tempo": SUBNET_TEMPO})
    submit_sudo_extrinsic(
        "sudo_set_hotkey_emission_tempo", {"emission_tempo": EMISSION_TEMPO}
    )

    btcli.stake_add(
        amount=10000,
        max_stake=15000,
        stake_all=False,
        include_hotkeys=validator_wallet.hotkey.ss58_address,
        hotkey_ss58_address=validator_wallet.hotkey.ss58_address,
        exclude_hotkeys=None,
        wallet_name=validator_wallet.name,
        wallet_path=validator_wallet.path,
        all_hotkeys=False,
        wallet_hotkey=validator_wallet.hotkey_str,
        quiet=False,
        network=NETWORK_TYPE,
        chain=NETWORK_URL,
    )

    btcli.wallet_transfer(
        destination_ss58_address=validator_wallet.coldkey.ss58_address,
        amount=10000,
        wallet_name=alice_wallet.name,
        wallet_hotkey=alice_wallet.hotkey_str,
        wallet_path=alice_wallet.path,
        quiet=False,
        network=NETWORK_TYPE,
        chain=NETWORK_URL,
    )

    btcli.root_set_weights(
        netuids=None,
        weights=None,
        wallet_name=None,
        wallet_hotkey=None,
        wallet_path=None,
        quiet=False,
        network=NETWORK_TYPE,
        chain=NETWORK_URL,
    )


if __name__ == "__main__":
    init()
