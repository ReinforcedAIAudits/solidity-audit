import dotenv
from typing import Tuple
import bittensor
from bittensor_wallet import Wallet
from substrateinterface import SubstrateInterface, Keypair
from websocket import WebSocketConnectionClosedException

# Constants
OWNER_NAME = "owner"
VALIDATOR_NAME = "validator"
MINER_NAME = "miner"
ROOT_ID = 0
SUBNET_TEMPO = 10
EMISSION_TEMPO = 30
NETWORK_TYPE = "local"
NETWORK_URL = "ws://127.0.0.1:9946"
RETRY_COUNT = 5
RETRY_DELAY = 5 

substrate = None
subtensor = None
# Initialize Subtensor and Substrate Interface
for attempt in range(RETRY_COUNT):
    try:
        substrate = SubstrateInterface(url=NETWORK_URL)
        subtensor = bittensor.subtensor(network=NETWORK_URL)
        break
    except Exception as ex:
        print(f"[ERROR] Exception while connecting to chain {ex}")
        time.sleep(RETRY_DELAY)

if not substrate or subtensor:
    raise ConnectionError("Cannot connect to chain!")

# Keypairs
keypair_alice = Keypair.create_from_uri("//Alice")

dotenv_file = dotenv.find_dotenv()
dotenv.load_dotenv(dotenv_path=dotenv_file)

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


def submit_extrinsic(
    pallet: str, method: str, params: dict, keypair: Keypair = keypair_alice
):
    try:
        receipt = substrate.submit_extrinsic(
            create_extrinsic(pallet, method, params, keypair),
            wait_for_finalization=True,
            wait_for_inclusion=True,
        )
        if not receipt.is_success:
            raise ValueError(
                f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}"
            )
        return receipt
    except (
        WebSocketConnectionClosedException,
        BrokenPipeError,
    ):
        substrate.connect_websocket()


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


def extract_net_id_from_events(events: list) -> int:
    for event in list(map(lambda e: e.value, events)):
        if (
            event["module_id"] == "SubtensorModule"
            and event["event_id"] == "NetworkAdded"
        ):
            net_uid = event["attributes"][0]
            dotenv.set_key(dotenv_path=dotenv_file, key_to_set="NETWORK_UID", value_to_set=str(net_uid))
            return net_uid
    raise ValueError(f"Not found network creation in {events}")


def setup_wallet(uri: str) -> Tuple[bittensor.Keypair, bittensor.wallet]:
    keypair = bittensor.Keypair.create_from_uri(uri)
    wallet_path = f"/tmp/btcli-wallet-{uri.strip('/')}"
    wallet = bittensor.wallet(path=wallet_path)

    wallet.set_coldkey(keypair=keypair, encrypt=False, overwrite=True)
    wallet.set_coldkeypub(keypair=keypair, encrypt=False, overwrite=True)
    wallet.set_hotkey(keypair=keypair, encrypt=False, overwrite=True)

    return keypair, wallet


def transfer_funds_if_needed(wallet: bittensor.wallet, alice_wallet: bittensor.wallet):
    if subtensor.get_balance(wallet.coldkey.ss58_address).tao < 10000.0:
        submit_extrinsic(
            "Balances",
            "transfer_allow_death",
            {"dest": wallet.coldkey.ss58_address, "value": 15000000000000},
        )
        print(f"[INFO] Money successfully transferred to {wallet.name}.")


def init():
    _, alice_wallet = setup_wallet("//Alice")

    for name in [OWNER_NAME, VALIDATOR_NAME, MINER_NAME]:
        wallet = (
            Wallet(name)
            .create_new_coldkey(n_words=21, use_password=False, overwrite=True)
            .create_new_hotkey(n_words=21, use_password=False, overwrite=True)
        )
        transfer_funds_if_needed(wallet, alice_wallet)

    # Get wallets
    owner_wallet = Wallet(OWNER_NAME, "default")
    validator_wallet = Wallet(VALIDATOR_NAME, "default")
    miner_wallet = Wallet(MINER_NAME, "default")

    # Register commands
    register_network_receipt = submit_extrinsic(
        "SubtensorModule",
        "register_network",
        {"immunity_period": 0, "reg_allowed": True},
        owner_wallet.coldkey,
    )

    net_uid = extract_net_id_from_events(register_network_receipt.triggered_events)

    submit_extrinsic(
        "SubtensorModule",
        "root_register",
        {"hotkey": validator_wallet.hotkey.ss58_address},
        owner_wallet.coldkey,
    )

    for wallet in [validator_wallet, miner_wallet]:
        submit_extrinsic(
            "SubtensorModule",
            "burned_register",
            {
                "netuid": net_uid,
                "hotkey": wallet.hotkey.ss58_address,
            },
            owner_wallet.coldkey,
        )

    # Set various limits and tempos
    submit_sudo_extrinsic(
        "sudo_set_weights_set_rate_limit",
        {"netuid": net_uid, "weights_set_rate_limit": 0},
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
        {"netuid": net_uid, "target_registrations_per_interval": 1000},
    )
    submit_sudo_extrinsic("sudo_set_tx_rate_limit", {"tx_rate_limit": 0})
    submit_sudo_extrinsic("sudo_set_tempo", {"netuid": net_uid, "tempo": SUBNET_TEMPO})
    submit_sudo_extrinsic("sudo_set_tempo", {"netuid": ROOT_ID, "tempo": SUBNET_TEMPO})
    submit_sudo_extrinsic(
        "sudo_set_hotkey_emission_tempo", {"emission_tempo": EMISSION_TEMPO}
    )

    submit_extrinsic(
        "SubtensorModule",
        "add_stake",
        {
            "hotkey": validator_wallet.hotkey.ss58_address,
            "amount_staked": 10000000000000,
        },
        validator_wallet.coldkey,
    )

    submit_extrinsic(
        "Balances",
        "transfer_allow_death",
        {"dest": validator_wallet.coldkey.ss58_address, "value": 10000000000000},
    )

    submit_extrinsic(
        "SubtensorModule",
        "set_root_weights",
        {
            "dests": [0, net_uid],
            "weights": [65, 65],
            "netuid": 0,
            "version_key": 0,
            "hotkey": validator_wallet.hotkey.ss58_address,
        },
        owner_wallet.coldkey,
    )


if __name__ == "__main__":
    init()
