import time
from typing import List, Tuple
import bittensor
from bittensor.commands.network import RegisterSubnetworkCommand, SubnetSudoCommand
from bittensor.commands.register import RegisterCommand
from bittensor.commands.root import RootRegisterCommand, RootSetWeightsCommand
from bittensor.commands.transfer import TransferCommand
from bittensor.commands.wallets import WalletCreateCommand
from bittensor.commands.stake import StakeCommand
from substrateinterface import SubstrateInterface, Keypair

# Constants
OWNER_NAME = "owner"
VALIDATOR_NAME = "validator"
MINER_NAME = "miner"
ROOT_ID = 0
NET_UID = 1
SUBNET_TEMPO = 10
EMISSION_TEMPO = 30
NETWORK_URL = "ws://localhost:9946"

# Initialize Subtensor and Substrate Interface
subtensor = bittensor.subtensor(network=NETWORK_URL)
interface = SubstrateInterface(NETWORK_URL)

# Keypairs
keypair_alice = Keypair.create_from_uri("//Alice")


def create_extrinsic(
    pallet: str, method: str, params: dict, keypair: Keypair = keypair_alice
):
    return interface.create_signed_extrinsic(
        call=interface.compose_call(
            call_module=pallet, call_function=method, call_params=params
        ),
        keypair=keypair,
    )


def create_sudo_extrinsic(
    pallet: str, method: str, params: dict, keypair: Keypair = keypair_alice
):
    return interface.create_signed_extrinsic(
        call=interface.compose_call(
            call_module="Sudo",
            call_function="sudo",
            call_params={
                "call": interface.compose_call(
                    call_module=pallet, call_function=method, call_params=params
                ).value
            },
        ),
        keypair=keypair,
    )


def submit_sudo_extrinsic(method: str, params: dict):
    receipt = interface.submit_extrinsic(
        create_sudo_extrinsic("AdminUtils", method, params), wait_for_finalization=True
    )
    if not receipt.is_success:
        raise ValueError(
            f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
        )


def exec_command(command, extra_args: List[str], wallet_path=None):
    parser = bittensor.cli.__create_parser__()
    args = extra_args + ["--no_prompt", "--subtensor.network", NETWORK_URL]
    if wallet_path:
        args.extend(["--wallet.path", wallet_path])

    config = bittensor.config(parser=parser, args=args)
    cli_instance = bittensor.cli(config)

    try:
        command.run(cli_instance)
    except Exception as e:
        print(f"Error executing command {command}: {e}")


def setup_wallet(uri: str) -> Tuple[bittensor.Keypair, bittensor.wallet]:
    keypair = bittensor.Keypair.create_from_uri(uri)
    wallet_path = f"/tmp/btcli-wallet-{uri.strip('/')}"
    wallet = bittensor.wallet(path=wallet_path)

    wallet.set_coldkey(keypair=keypair, encrypt=False, overwrite=True)
    wallet.set_coldkeypub(keypair=keypair, encrypt=False, overwrite=True)
    wallet.set_hotkey(keypair=keypair, encrypt=False, overwrite=True)

    return keypair, wallet


def create_wallet(name: str):
    exec_command(
        WalletCreateCommand,
        [
            "wallet",
            "create",
            "--wallet.name",
            name,
            "--wallet.hotkey",
            "default",
            "--no_password",
            "--overwrite_coldkey",
            "--overwrite_hotkey",
            "--no_prompt",
        ],
    )


def transfer_funds_if_needed(wallet: bittensor.wallet, alice_wallet: bittensor.wallet):
    if subtensor.get_balance(wallet.coldkey.ss58_address).tao < 10000.0:
        exec_command(
            TransferCommand,
            [
                "wallet",
                "transfer",
                "--amount",
                "15000",
                "--dest",
                wallet.coldkey.ss58_address,
            ],
            alice_wallet.path,
        )


# Setup wallets
alice_keypair, alice_wallet = setup_wallet("//Alice")
alice_hot = bittensor.Keypair.create_from_uri("//AliceHot")

for name in [OWNER_NAME, VALIDATOR_NAME, MINER_NAME]:
    create_wallet(name)
    wallet = bittensor.wallet(name, "default")
    transfer_funds_if_needed(wallet, alice_wallet)

# Get wallets
owner_wallet = bittensor.wallet(OWNER_NAME, "default")
validator_wallet = bittensor.wallet(VALIDATOR_NAME, "default")
miner_wallet = bittensor.wallet(MINER_NAME, "default")

# Register commands
exec_command(
    RegisterSubnetworkCommand,
    ["s", "create", "--netuid", str(NET_UID), "--wallet.name", owner_wallet.name],
    owner_wallet.path,
)

exec_command(
    RootRegisterCommand,
    [
        "root",
        "register",
        "--netuid",
        str(NET_UID),
        "--wallet.name",
        validator_wallet.name,
    ],
    validator_wallet.path,
)

for wallet in [validator_wallet, miner_wallet]:
    exec_command(
        RegisterCommand,
        ["s", "register", "--netuid", str(NET_UID), "--wallet.name", wallet.name],
        wallet.path,
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

exec_command(
    StakeCommand,
    [
        "stake",
        "add",
        "--amount",
        "10000",
        "--wallet.name",
        validator_wallet.name,
        "--hotkey",
        validator_wallet.hotkey_str,
    ],
)
exec_command(
    TransferCommand,
    [
        "wallet",
        "transfer",
        "--amount",
        "15000",
        "--dest",
        validator_wallet.coldkey.ss58_address,
    ],
    alice_wallet.path,
)

for netuid in [ROOT_ID, NET_UID]:
    exec_command(
        RootSetWeightsCommand,
        [
            "r",
            "weights",
            "--netuid",
            str(netuid),
            "--weights",
            "33",
            "--wallet.name",
            validator_wallet.name,
            "--wait_for_finalization",
            "True",
        ],
        validator_wallet.path,
    )
