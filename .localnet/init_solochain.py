import os
import shutil
import time
import typing

import dotenv
from typing import Tuple
import bittensor
from bittensor_wallet import Wallet
from substrateinterface import SubstrateInterface, Keypair
from websocket import WebSocketConnectionClosedException


__all__ = ["SoloChainHelper"]


PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class SoloChainHelper:
    OWNER_NAME = "owner"
    VALIDATOR_NAME = "validator"
    MINER_NAME = "miner"
    ROOT_ID = 0
    SUBNET_TEMPO = 10
    EMISSION_TEMPO = 30
    NETWORK_TYPE = "local"
    RETRY_COUNT = 5
    RETRY_DELAY = 5

    def __init__(self, network_url=None):
        self.substrate = None
        self.subtensor = None
        self.network_url = os.getenv("CHAIN_ENDPOINT", "ws://127.0.0.1:9944") if network_url is None else network_url
        self.keypair_alice = Keypair.create_from_uri("//Alice")

    def connect(self):
        # Initialize Subtensor and Substrate Interface
        for attempt in range(self.RETRY_COUNT):
            try:
                self.substrate = SubstrateInterface(url=self.network_url)
                self.subtensor = bittensor.subtensor(network=self.network_url)
                break
            except Exception as ex:
                print(f"[ERROR] Exception while connecting to chain {ex}")
                time.sleep(self.RETRY_DELAY)
        return self

    @staticmethod
    def require_connect(func):
        def wrapped(self, *args, **kwargs):
            if not self.substrate or not self.subtensor:
                raise ConnectionError(f"Cannot connect to chain with URL: {self.network_url}!")
            return func(self, *args, **kwargs)

        return wrapped

    @require_connect
    def create_extrinsic(
        self,
        pallet: str,
        method: str,
        params: dict,
        keypair: typing.Optional[Keypair] = None,
    ):
        keypair = self.keypair_alice if keypair is None else keypair
        return self.substrate.create_signed_extrinsic(
            call=self.substrate.compose_call(call_module=pallet, call_function=method, call_params=params),
            keypair=keypair,
        )

    @require_connect
    def create_sudo_extrinsic(self, pallet: str, method: str, params: dict, keypair: Keypair = None):
        keypair = self.keypair_alice if keypair is None else keypair
        return self.substrate.create_signed_extrinsic(
            call=self.substrate.compose_call(
                call_module="Sudo",
                call_function="sudo",
                call_params={
                    "call": self.substrate.compose_call(
                        call_module=pallet, call_function=method, call_params=params
                    ).value
                },
            ),
            keypair=keypair,
        )

    @require_connect
    def submit_extrinsic(self, pallet: str, method: str, params: dict, keypair: Keypair = None):
        keypair = self.keypair_alice if keypair is None else keypair
        try:
            receipt = self.substrate.submit_extrinsic(
                self.create_extrinsic(pallet, method, params, keypair),
                wait_for_finalization=True,
                wait_for_inclusion=True,
            )
            if not receipt.is_success:
                raise ValueError(f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}")
            return receipt
        except (
            WebSocketConnectionClosedException,
            BrokenPipeError,
        ):
            self.substrate.connect_websocket()

    @require_connect
    def submit_sudo_extrinsic(self, method: str, params: dict):
        try:
            receipt = self.substrate.submit_extrinsic(
                self.create_sudo_extrinsic("AdminUtils", method, params),
                wait_for_finalization=True,
                wait_for_inclusion=True,
            )
            if not receipt.is_success:
                raise ValueError(f"Failed extrinsic {receipt.extrinsic_hash} with {receipt.error_message}")
        except (
            WebSocketConnectionClosedException,
            BrokenPipeError,
        ):
            self.substrate.connect_websocket()

    @classmethod
    def extract_net_id_from_events(cls, events: list) -> int:
        for event in list(map(lambda e: e.value, events)):
            if event["module_id"] == "SubtensorModule" and event["event_id"] == "NetworkAdded":
                net_uid = event["attributes"][0]
                dotenv.set_key(
                    dotenv_path=dotenv_file,
                    key_to_set="NETWORK_UID",
                    value_to_set=str(net_uid),
                )
                return net_uid
        raise ValueError(f"Not found network creation in {events}")

    @classmethod
    def setup_wallet(cls, uri: str) -> Tuple[bittensor.Keypair, bittensor.wallet]:
        keypair = bittensor.Keypair.create_from_uri(uri)
        wallet_path = f"/tmp/btcli-wallet-{uri.strip('/')}"
        wallet = bittensor.wallet(path=wallet_path)

        wallet.set_coldkey(keypair=keypair, encrypt=False, overwrite=True)
        wallet.set_coldkeypub(keypair=keypair, encrypt=False, overwrite=True)
        wallet.set_hotkey(keypair=keypair, encrypt=False, overwrite=True)

        return keypair, wallet

    @require_connect
    def transfer_funds_if_needed(self, wallet: bittensor.wallet, alice_wallet: bittensor.wallet):
        if self.subtensor.get_balance(wallet.coldkey.ss58_address).tao < 10000.0:
            self.submit_extrinsic(
                "Balances",
                "transfer_allow_death",
                {"dest": wallet.coldkey.ss58_address, "value": 15000000000000},
            )
            print(f"[INFO] Money successfully transferred to {wallet.name}.")

    def init_solo_chain(self):
        _, alice_wallet = self.setup_wallet("//Alice")

        for name in [self.OWNER_NAME, self.VALIDATOR_NAME, self.MINER_NAME]:
            wallet = (
                Wallet(name)
                .create_new_coldkey(n_words=21, use_password=False, overwrite=True)
                .create_new_hotkey(n_words=21, use_password=False, overwrite=True)
            )
            self.transfer_funds_if_needed(wallet, alice_wallet)

        # Get wallets
        owner_wallet = Wallet(self.OWNER_NAME, "default")
        validator_wallet = Wallet(self.VALIDATOR_NAME, "default")
        miner_wallet = Wallet(self.MINER_NAME, "default")

        # Register commands
        register_network_receipt = self.submit_extrinsic(
            "SubtensorModule",
            "register_network",
            {"immunity_period": 0, "reg_allowed": True},
            owner_wallet.coldkey,
        )

        net_uid = self.extract_net_id_from_events(register_network_receipt.triggered_events)

        self.submit_extrinsic(
            "SubtensorModule",
            "root_register",
            {"hotkey": owner_wallet.hotkey.ss58_address},
            owner_wallet.coldkey,
        )

        for wallet in [validator_wallet, miner_wallet]:
            self.submit_extrinsic(
                "SubtensorModule",
                "burned_register",
                {
                    "netuid": net_uid,
                    "hotkey": wallet.hotkey.ss58_address,
                },
                wallet.coldkey,
            )

        # Set various limits and tempos
        self.submit_sudo_extrinsic(
            "sudo_set_weights_set_rate_limit",
            {"netuid": net_uid, "weights_set_rate_limit": 0},
        )
        self.submit_sudo_extrinsic(
            "sudo_set_weights_set_rate_limit",
            {"netuid": self.ROOT_ID, "weights_set_rate_limit": 0},
        )
        self.submit_sudo_extrinsic("sudo_set_target_stakes_per_interval", {"target_stakes_per_interval": 1000})
        self.submit_sudo_extrinsic(
            "sudo_set_target_registrations_per_interval",
            {"netuid": net_uid, "target_registrations_per_interval": 1000},
        )
        self.submit_sudo_extrinsic("sudo_set_tx_rate_limit", {"tx_rate_limit": 0})
        self.submit_sudo_extrinsic("sudo_set_tempo", {"netuid": net_uid, "tempo": self.SUBNET_TEMPO})
        self.submit_sudo_extrinsic("sudo_set_tempo", {"netuid": self.ROOT_ID, "tempo": self.SUBNET_TEMPO})
        self.submit_sudo_extrinsic("sudo_set_hotkey_emission_tempo", {"emission_tempo": self.EMISSION_TEMPO})

        self.submit_extrinsic(
            "SubtensorModule",
            "add_stake",
            {
                "hotkey": validator_wallet.hotkey.ss58_address,
                "amount_staked": 10000000000000,
            },
            validator_wallet.coldkey,
        )

        self.submit_extrinsic(
            "Balances",
            "transfer_allow_death",
            {"dest": validator_wallet.coldkey.ss58_address, "value": 10000000000000},
        )

        self.submit_extrinsic(
            "SubtensorModule",
            "set_root_weights",
            {
                "dests": [0, net_uid],
                "weights": [65, 65],
                "netuid": 0,
                "version_key": 0,
                "hotkey": owner_wallet.hotkey.ss58_address,
            },
            owner_wallet.coldkey,
        )


if __name__ == "__main__":
    DOT_ENV_PATH = os.path.join(PARENT_DIR, ".env")
    if not os.path.exists(DOT_ENV_PATH):
        shutil.copy(os.path.join(PARENT_DIR, ".env-example"), DOT_ENV_PATH)
    dotenv_file = dotenv.find_dotenv()
    dotenv.load_dotenv(dotenv_path=dotenv_file)
    SoloChainHelper().connect().init_solo_chain()
