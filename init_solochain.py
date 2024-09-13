from typing import List, Tuple
import bittensor
from bittensor.commands.network import RegisterSubnetworkCommand
from bittensor.commands.register import RegisterCommand
from bittensor.commands.root import RootRegisterCommand
from bittensor.commands.transfer import TransferCommand
from bittensor.commands.wallets import WalletCreateCommand

OWNER_NAME = "owner"
VALIDATOR_NAME = "validator"
MINER_NAME = "miner"

subtensor = bittensor.subtensor(network="ws://localhost:9946")


def exec_command(command, extra_args: List[str], wallet_path=None):
    parser = bittensor.cli.__create_parser__()
    args = extra_args + [
        "--no_prompt",
        "--subtensor.network",
        "ws://localhost:9946",
    ]
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


alice_keypair, alice_wallet = setup_wallet("//Alice")

for name in [OWNER_NAME, VALIDATOR_NAME, MINER_NAME]:
    create_wallet(name)
    wallet = bittensor.wallet(name, "default")
    transfer_funds_if_needed(wallet, alice_wallet)

owner_wallet = bittensor.wallet(OWNER_NAME, "default")
validator_wallet = bittensor.wallet(VALIDATOR_NAME, "default")
miner_wallet = bittensor.wallet(MINER_NAME, "default")

exec_command(
    RegisterSubnetworkCommand,
    [
        "s",
        "create",
        "--netuid",
        "1",
        "--wallet.name",
        owner_wallet.name,
    ],
    owner_wallet.path,
)

exec_command(
    RootRegisterCommand,
    [
        "root",
        "register",
        "--netuid",
        "1",
        "--wallet.name",
        validator_wallet.name,
    ],
    validator_wallet.path,
)

for wallet in [validator_wallet, miner_wallet]:
    exec_command(
        RegisterCommand,
        [
            "s",
            "register",
            "--netuid",
            "1",
            "--wallet.name",
            wallet.name,
        ],
        wallet.path,
    )
