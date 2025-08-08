import collections
import dataclasses
import logging
import os
import sys
import time

import requests
import uvicorn
from bittensor_wallet import Keypair
from substrateinterface import Keypair as CryptoKeypair

from solidity_audit_lib import SubtensorWrapper
from solidity_audit_lib.relayer_client.client import RelayerClient
from solidity_audit_lib.relayer_client.relayer_types import RegisterParams
from unique_playgrounds import UniqueHelper

from ai_audits.subnet_utils import create_session
from config import Config


__all__ = ["ReinforcedNeuron", "ReinforcedConfig", "ScoresBuffer", "ReinforcedError"]


class ScoresBuffer:
    DEFAULT = object()
    U16_MAX = 65535

    def __init__(self, max_size=100):
        self.max_size = max_size
        self._items = {}

    def __getitem__(self, uid):
        self._check_uid(uid)
        if uid not in self._items:
            raise KeyError("No scores for neuron uid")
        return self._items[uid]

    def __setitem__(self, uid, scores):
        if not isinstance(uid, int):
            raise KeyError("Neuron uid must be int")
        if not isinstance(scores, (list, collections.deque)):
            raise ValueError("Scores must be list")
        buff = collections.deque(maxlen=self.max_size)
        for score in scores:
            self._check_score(score)

        buff.extend(scores)
        self._items[uid] = buff

    def get(self, item, default=DEFAULT):
        if default is self.DEFAULT:
            default = collections.deque(maxlen=self.max_size)
        return self._items.get(item, default)

    @classmethod
    def _check_score(cls, score):
        if not isinstance(score, (int, float)):
            raise ValueError("Invalid score type")
        if score > 1:
            raise ValueError("Score must be <= 1")

    @classmethod
    def _check_uid(cls, uid: int):
        if not isinstance(uid, int):
            raise KeyError("Neuron uid must be int")

    def add_score(self, uid, score):
        self._check_uid(uid)
        self._check_score(score)

        buff = self.get(uid)
        buff.append(score)
        self._items[uid] = buff

    def reset(self, uid):
        self._check_uid(uid)
        self._items.pop(uid, None)

    def dump(self):
        return {str(k): list(v) for k, v in self._items.items()}

    def load(self, value: dict):
        self._items = {}
        for uid, scores in value.items():
            self[int(uid)] = scores

    def uids(self):
        return list(k for k, v in self._items.items() if v)

    def scores(self):
        prepared_scores = []
        for uid, scores in self._items.items():
            if not len(scores):
                continue
            score = sum(scores) / len(scores)
            prepared_scores.append(round(score * int(self.U16_MAX)))
        return prepared_scores


@dataclasses.dataclass
class ReinforcedConfig:
    ws_endpoint: str
    net_uid: int


class ReinforcedError(Exception):
    pass


@dataclasses.dataclass
class ReinforcedSettings:
    relayer_ip: str
    relayer_port: int
    unique_endpoint: str
    network_id: int
    trusted_keys: list[str]


class ReinforcedNeuron:
    NEURON_TYPE = 'Base'
    AXONS_CACHE_INVALIDATION = 5 * 60
    UID_CACHE_INVALIDATION = 5 * 60
    settings: ReinforcedSettings

    def __init__(self, config: ReinforcedConfig):
        self.log = logging.getLogger(f'reinforced.{self.NEURON_TYPE}')
        self.config = config
        hotkey = Config.MNEMONIC_HOTKEY.strip()
        if hotkey.startswith('0x'):
            hotkey_size = len(hotkey) // 2 - 1
            if hotkey_size not in (32, 64):
                raise ReinforcedError('Invalid MNEMONIC_HOTKEY, only seed phrase, seed and full private key supported')
            self.hotkey = (
                Keypair.create_from_private_key(hotkey) if hotkey_size == 64 else
                Keypair.create_from_seed(hotkey)
            )
            self.crypto_hotkey = (
                CryptoKeypair.create_from_private_key(hotkey, ss58_format=42) if hotkey_size == 64 else
                CryptoKeypair.create_from_seed(hotkey, ss58_format=42)
            )
        else:
            self.hotkey = Keypair.create_from_uri(hotkey)
            self.crypto_hotkey = CryptoKeypair.create_from_uri(hotkey)

        self._axons_cache = None
        self._axons_cache_time = 0
        self.uid = None
        self.ip = Config.EXTERNAL_IP
        self.port = Config.BT_AXON_PORT
        self._uid_check_time = 0
        self.log_handler = None
        self.init_logging()
        self.get_settings()
        self.relayer_client = RelayerClient(
            f'http://{self.settings.relayer_ip}:{self.settings.relayer_port}',
            self.settings.network_id, self.config.net_uid
        )

    def get_settings(self):
        settings = create_session().get(f'{Config.SECURE_WEB_URL}/config/settings.json').json()
        relayer = [x for x in settings['relayers'] if x['network'] == Config.NETWORK_TYPE][0]
        self.settings = ReinforcedSettings(
            unique_endpoint=settings['unique_endpoint'], trusted_keys=settings['trusted_keys'],
            relayer_ip=relayer['ip'], relayer_port=relayer['port'], network_id=relayer['network_id']
        )

    def init_logging(self):
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
        self.log.addHandler(handler)
        self.log.setLevel(logging.DEBUG)

    def check_nft_collection_ownership(self, collection_id: int, owner: str) -> bool:
        with UniqueHelper(self.settings.unique_endpoint) as helper:
            collection = helper.nft.get_collection_info(collection_id)

        if not collection:
            self.log.error(f"Collection #{collection_id} not found")
            return False

        if collection["owner"] != helper.address.normalize(owner):
            self.log.error(f"Collection #{collection_id} not owned by {owner}")
            return False

        return True

    def get_nft_nonce(self):
        with UniqueHelper(self.settings.unique_endpoint) as helper:
            return helper.call_query("System", "Account", [self.hotkey.ss58_address]).value["nonce"]

    def get_axons(self):
        now = time.time()
        if (now - self._axons_cache_time) > self.AXONS_CACHE_INVALIDATION:
            with SubtensorWrapper(self.config.ws_endpoint) as client:
                self._axons_cache = client.get_axons(self.config.net_uid)
            self._axons_cache_time = now
            self.log.debug("Axons cache updated")
        return self._axons_cache

    def get_current_uid(self):
        with SubtensorWrapper(self.config.ws_endpoint) as client:
            self.log.info('Checking current uid')
            old_uid = self.uid
            self.uid = client.get_uid(self.config.net_uid, self.hotkey.ss58_address)
            self._uid_check_time = time.time()
            if old_uid != self.uid:
                self.log.info(f'uid changed from {old_uid} to {self.uid}')

    def check_axon_alive(self):
        now = time.time()
        if (now - self._uid_check_time) > self.UID_CACHE_INVALIDATION:
            self.get_current_uid()

        if self.uid is None:
            self.log.error(
                f'Axon for hotkey {self.hotkey.ss58_address} not registered in net uid: {self.config.net_uid}'
            )
            self.log.debug(f"Axon with hotkey {self.hotkey.ss58_address} not found")
            raise ReinforcedError('Axon not registered')

    def serve_axon(self):
        while True:
            with SubtensorWrapper(self.config.ws_endpoint) as client:
                uid = client.get_uid(self.config.net_uid, self.hotkey.ss58_address)
                if uid is None:
                    self.log.error(
                        f'Axon for hotkey {self.hotkey.ss58_address} not registered in net uid: {self.config.net_uid}'
                    )
                    raise ReinforcedError('Axon not registered')
                result = self.relayer_client.register_axon(self.hotkey, RegisterParams(
                    uid=uid, ip=self.ip,
                    port=self.port,
                    type=self.NEURON_TYPE
                ))
                if not result.success:
                    self.log.warning('Unable to register at relayer, need wait for sync...')
                    time.sleep(60)
                    continue
                self.uid = uid
                self._uid_check_time = time.time()
                result, error = client.serve_axon(
                    self.hotkey, self.config.net_uid, ip=self.settings.relayer_ip, port=self.settings.relayer_port
                )
                if result:
                    self.log.info(f'Axon serving, net uid: {self.config.net_uid}, uid: {uid}, ss58 address: {self.hotkey.ss58_address}')
                    break
                self.log.warning(f'Unable to perform serve_axon. Need to wait {error["blocks"]} blocks')
            time.sleep(error['blocks'] * 6)

    @classmethod
    def serve_uvicorn(cls, app):
        uvicorn.run(app, host="0.0.0.0", port=Config.BT_AXON_PORT, log_level='error')

    @classmethod
    def code_version(cls):
        version = getattr(cls, '_code_version', None)
        if version is None:
            with open(os.path.join(Config.BASE_DIR, 'requirements.version.txt'), 'r') as f:
                current_version = f.read().strip()
            setattr(cls, '_code_version', current_version)
        return getattr(cls, '_code_version')

    @classmethod
    def current_version(cls) -> tuple[str, str]:
        current_version = cls.code_version()
        config = create_session().get(f'{Config.SECURE_WEB_URL}/config/settings.json').json()
        version = None
        try:
            for ver in config['versions']:
                if ver['network'] == Config.NETWORK_TYPE:
                    version = ver['version']
                    break
        except:
            pass
        return current_version, version

    def wait_for_server(self, url, max_attempts=10, delay=5):
        if Config.SKIP_HEALTHCHECK:
            return True
        for _ in range(max_attempts):
            try:
                if requests.get(f"{url}/healthcheck").status_code == 200:
                    return True
            except requests.RequestException:
                pass
            self.log.warning(f"Server is not running yet. Waiting {delay} seconds to connect...")
            time.sleep(delay)
        return False
