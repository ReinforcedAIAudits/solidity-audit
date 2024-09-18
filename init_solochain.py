import time
from typing import List, Tuple
import bittensor
from bittensor.commands.network import RegisterSubnetworkCommand, SubnetSudoCommand
from bittensor.commands.register import RegisterCommand
from bittensor.commands.root import RootRegisterCommand
from bittensor.commands.transfer import TransferCommand
from bittensor.commands.wallets import WalletCreateCommand
from bittensor.commands.stake import StakeCommand
from substrateinterface import SubstrateInterface, Keypair


OWNER_NAME = "owner"
VALIDATOR_NAME = "validator"
MINER_NAME = "miner"
ROOT_ID = 0
NET_UID = 1
SUBNET_TEMPO = 10
EMISSION_TEMPO = 30

subtensor = bittensor.subtensor(network="ws://localhost:9946")
interface = SubstrateInterface("ws://localhost:9946")

keypair_alice = Keypair.create_from_uri("//Alice")
keypair_bob = Keypair.create_from_uri("//Bob")


def create_extrinsic(
    pallet: str, method: str, params: dict, keypair: Keypair = keypair_alice
):
    return interface.create_signed_extrinsic(
        call=interface.compose_call(
            call_module=pallet,
            call_function=method,
            call_params=params,
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
                    call_module=pallet,
                    call_function=method,
                    call_params=params,
                ).value
            },
        ),
        keypair=keypair,
    )


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

print(subtensor.get_subnet_owner(1))
print(subtensor.get_subnet_owner(0))

print(owner_wallet.coldkeypub.ss58_address)
print(validator_wallet.coldkeypub.ss58_address)
print(miner_wallet.coldkeypub.ss58_address)

print(alice_keypair.ss58_address)
print(keypair_bob.ss58_address)

# receipt = interface.submit_extrinsic(
#     create_extrinsic(
#         "SubtensorModule",
#         "burned_register",
#         {"netuid": 0, "hotkey": alice_keypair.ss58_address},
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

receipt = interface.submit_extrinsic(
    create_extrinsic(
        "SubtensorModule",
        "burned_register",
        {"netuid": 1, "hotkey": alice_keypair.ss58_address},
    ),
    wait_for_finalization=True,
)

if not receipt.is_success:
    raise ValueError(
        f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
    )


receipt = interface.submit_extrinsic(
    create_extrinsic(
        "SubtensorModule",
        "burned_register",
        {"netuid": 1, "hotkey": keypair_bob.ss58_address},
    ),
    wait_for_finalization=True,
)

if not receipt.is_success:
    raise ValueError(
        f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
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

# exec_command(
#     SubnetSudoCommand,
#     [
#         "sudo",
#         "set",
#         "--netuid",
#         "1",
#         "--param",
#         "weights_rate_limit",
#         "--value",
#         "0",
#         "--wallet.name",
#         owner_wallet.name,
#     ],
# )

# # exec_command(
# #     SubnetSudoCommand,
# #     [
# #         "sudo",
# #         "set",
# #         "--netuid",
# #         "0",
# #         "--param",
# #         "weights_rate_limit",
# #         "--value",
# #         "0",
# #         "--wallet.name",
# #         owner_wallet.name,
# #     ],
# # )

# receipt = interface.submit_extrinsic(
#     create_sudo_extrinsic(
#         "AdminUtils",
#         "sudo_set_weights_set_rate_limit",
#         {"netuid": 0, "weights_set_rate_limit": 0}
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

# receipt = interface.submit_extrinsic(
#     create_sudo_extrinsic(
#         "AdminUtils",
#         "sudo_set_target_stakes_per_interval",
#         {"target_stakes_per_interval": 1000},
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

# # exec_command(
# #     SubnetSudoCommand,
# #     [
# #         "sudo",
# #         "set",
# #         "--netuid",
# #         "1",
# #         "--param",
# #         "target_regs_per_interval",
# #         "--value",
# #         "1000",
# #         "--wallet.name",
# #         owner_wallet.name,
# #     ],
# # )

# receipt = interface.submit_extrinsic(
#     create_sudo_extrinsic(
#         "AdminUtils",
#         "sudo_set_target_registrations_per_interval",
#         {"netuid": 1, "target_registrations_per_interval": 1000},
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

# receipt = interface.submit_extrinsic(
#     create_sudo_extrinsic(
#         "AdminUtils",
#         "sudo_set_tx_rate_limit",
#         {"tx_rate_limit": 0},
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

# receipt = interface.submit_extrinsic(
#     create_sudo_extrinsic(
#         "AdminUtils",
#         "sudo_set_tempo",
#         {"netuid": 1, "tempo": 10},
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

# receipt = interface.submit_extrinsic(
#     create_sudo_extrinsic(
#         "AdminUtils",
#         "sudo_set_tempo",
#         {"netuid": 0, "tempo": 10},
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )
# # exec_command(
# #     SubnetSudoCommand,
# #     [
# #         "sudo",
# #         "set",
# #         "--netuid",
# #         "1",
# #         "--param",
# #         "tempo",
# #         "--value",
# #         "10",
# #         "--wallet.name",
# #         owner_wallet.name,
# #     ],
# # )

# # exec_command(
# #     SubnetSudoCommand,
# #     [
# #         "sudo",
# #         "set",
# #         "--netuid",
# #         "0",
# #         "--param",
# #         "tempo",
# #         "--value",
# #         "10",
# #         "--wallet.name",
# #         owner_wallet.name,
# #     ],
# # )

# receipt = interface.submit_extrinsic(
#     create_sudo_extrinsic(
#         "AdminUtils",
#         "sudo_set_hotkey_emission_tempo",
#         {"emission_tempo": 30},
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

# receipt = interface.submit_extrinsic(
#     create_extrinsic(
#         "SubtensorModule",
#         "set_weights",
#         {"netuid": 1, "dests": [0, 1], "weights": [0, 0], "version_key": 0},
#         keypair_bob,
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

# receipt = interface.submit_extrinsic(
#     create_extrinsic(
#         "SubtensorModule",
#         "set_root_weights",
#         {
#             "netuid": 0,
#             "hotkey": alice_keypair.ss58_address,
#             "dests": [0, 1],
#             "weights": [65535, 65535],
#             "version_key": 0,
#         },
#     ),
#     wait_for_finalization=True,
# )

# if not receipt.is_success:
#     raise ValueError(
#         f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
#     )

exec_command(
    StakeCommand,
    [
        "stake",
        "add",
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
