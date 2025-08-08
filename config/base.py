import os
from dotenv import load_dotenv
from bittensor.utils import networking as net


try:
    load_dotenv()
except Exception as e:
    print(f"Failed to load environment variables: {e}")
    exit(1)


class BaseConfig:
    CHAIN_ENDPOINT: str = os.getenv("CHAIN_ENDPOINT", "wss://test.finney.opentensor.ai:443")
    NETWORK_TYPE: str = os.getenv("NETWORK_TYPE", "testnet")
    NETWORK_UID = 92 if NETWORK_TYPE == "mainnet" else 222
    MNEMONIC_HOTKEY: str = os.getenv("MNEMONIC_HOTKEY", "//Alice")
    EXTERNAL_IP = os.getenv('EXTERNAL_IP', net.get_external_ip())
    BT_AXON_PORT = int(os.getenv('BT_AXON_PORT', '8091'))

    MAX_MINER_FORWARD_REQUESTS = int(os.getenv("MAX_MINER_FORWARD_REQUESTS", 5))

    MODEL_SERVER = os.getenv('MODEL_SERVER')

    TASK_MAX_TRIES: int = int(os.getenv("MAX_TRIES", "3"))
    ESTIMATION_RETRIES: int = int(os.getenv("ESTIMATION_RETRIES", "3"))

    CYCLE_TIME = int(os.getenv("VALIDATOR_SEND_REQUESTS_EVERY_X_SECS", "3600"))

    MAX_BUFFER = int(os.getenv("VALIDATOR_BUFFER", "24"))
    VALIDATOR_TIME = os.getenv("VALIDATOR_TIME", None)
    REQUEST_PERIOD = int(os.getenv("MINER_ACCEPT_REQUESTS_EVERY_X_SECS", 20 * 60))
    SKIP_HEALTHCHECK = os.getenv("SKIP_HEALTHCHECK", "false").lower() == "true"
    WHITELISTED_KEYS = os.getenv("WHITELISTED_KEYS", "")
    SECURE_WEB_URL = 'https://secure.reinforced.app'
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
