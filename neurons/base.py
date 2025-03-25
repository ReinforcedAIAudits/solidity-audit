import collections
import dataclasses
import logging
import os
import sys
import time

import uvicorn
from async_substrate_interface.sync_substrate import Keypair
from bittensor.utils import networking as net
from solidity_audit_lib import SubtensorWrapper

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
        return {k: list(v) for k, v in self._items.items()}

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


class ReinforcedNeuron:
    NEURON_TYPE = 'Base'
    AXONS_CACHE_INVALIDATION = 5 * 60
    UID_CACHE_INVALIDATION = 5 * 60

    def __init__(self, config: ReinforcedConfig):
        self.log = logging.getLogger(f'reinforced.{self.NEURON_TYPE}')
        self.config = config
        self.hotkey = Keypair.create_from_uri(os.getenv('MNEMONIC_HOTKEY', '//Alice'))
        self.coldkey = Keypair.create_from_uri(os.getenv('MNEMONIC_COLDKEY', '//Alice'))
        self._axons_cache = None
        self._axons_cache_time = 0
        self.uid = None
        self._uid_check_time = 0
        self.log_handler = None
        self.init_logging()

    def init_logging(self):
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
        self.log.addHandler(handler)
        self.log.setLevel(logging.DEBUG)

    def get_axons(self):
        now = time.time()
        if (now - self._axons_cache_time) > self.AXONS_CACHE_INVALIDATION:
            with SubtensorWrapper(self.config.ws_endpoint) as client:
                self._axons_cache = client.get_axons(self.config.net_uid)
            self._axons_cache_time = now
            self.log.debug("Axons cache updated")
        return self._axons_cache

    def set_identity(self):
        description = os.getenv("COLDKEY_DESCRIPTION")
        if not description:
            return
        with SubtensorWrapper(self.config.ws_endpoint) as client:
            client.set_identity(self.coldkey, self.NEURON_TYPE, description)
        self.log.debug(f"Identity set for coldkey {self.coldkey.ss58_address}")

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
                self.uid = uid
                self._uid_check_time = time.time()
                result, error = client.serve_axon(
                    self.hotkey, self.config.net_uid, ip=os.getenv('EXTERNAL_IP', net.get_external_ip()),
                    port=int(os.getenv('BT_AXON_PORT', '8091'))
                )
                if result:
                    self.log.info(f'Axon serving, net uid: {self.config.net_uid}, uid: {uid}')
                    break
                self.log.warning(f'Unable to perform serve_axon. Need to wait {error["blocks"]} blocks')
            time.sleep(error['blocks'] * 6)

    @classmethod
    def serve_uvicorn(cls, app):
        uvicorn.run(app, host="0.0.0.0", port=int(os.getenv('BT_AXON_PORT', '8091')), log_level='error')

