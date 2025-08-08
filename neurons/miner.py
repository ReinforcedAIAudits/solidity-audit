import json
import sys
import time
import requests
from solidity_audit_lib.encrypting import encrypt
from solidity_audit_lib.messaging import VulnerabilityReport, MinerResponseMessage, MinerResponse
from solidity_audit_lib.relayer_client.relayer_types import TaskModel
from unique_playgrounds import UniqueHelper
from unique_playgrounds.types_system import SignParams
from unique_playgrounds.types_unique import CrossAccountId, Property

from ai_audits.protocol import MinerInfo, NFTMetadata
from config import Config
from neurons.base import ReinforcedNeuron, ReinforcedConfig
from neurons.server import AxonServer, AxonServerOptions

__all__ = ["Miner", "run_miner"]


class Miner(ReinforcedNeuron):
    NEURON_TYPE = "miner"
    REQUEST_PERIOD = Config.REQUEST_PERIOD
    MAX_TOKEN_SIZE = 1024 * 31
    _last_call: dict[str, float]
    _callers_whitelist: list[str]

    def __init__(self, config: ReinforcedConfig):
        super().__init__(config)
        self._last_call = {}
        self._callers_whitelist = list(
            set(self.settings.trusted_keys) | {key.strip() for key in Config.WHITELISTED_KEYS.split(",") if key.strip()}
        )
        self.collection_id = None
        self.nonce = self.get_nft_nonce()

    def create_nft_collection(self) -> int:
        existed = self.relayer_client.get_storage(self.hotkey)
        if existed.success and existed.result is not None and "collection_id" in existed.result:
            if self.check_nft_collection_ownership(existed.result["collection_id"], self.hotkey.ss58_address):
                self.collection_id = existed.result["collection_id"]
                self.log.info(f"Collection #{self.collection_id} found for {self.hotkey.ss58_address}")
                return self.collection_id
        collection_data = {
            "name": f"Miner {self.hotkey.ss58_address[:4]}...{self.hotkey.ss58_address[-4:]} "
            f"audits ({Config.NETWORK_TYPE})",
            "description": f"Collection of contract audits performed by miner {self.hotkey.ss58_address}.",
            "token_prefix": "AUD",
            "token_property_permissions": [
                {
                    "key": "validator",
                    "permission": {"mutable": False, "token_owner": False, "collection_admin": True},
                },
                {
                    "key": "audit",
                    "permission": {"mutable": False, "token_owner": False, "collection_admin": True},
                },
            ],
        }
        with UniqueHelper(self.settings.unique_endpoint) as helper:
            self.nonce = self.get_nft_nonce()
            collection = helper.nft.create_collection(self.hotkey, collection_data)
            collection_id = collection.collection_id

        self.relayer_client.set_storage(self.hotkey, MinerStorage(collection_id=collection_id))

        self.collection_id = collection_id
        self.log.info(f"Created collection #{self.collection_id} for {self.hotkey.ss58_address}")
        return self.collection_id

    def mint_token_with_nonce(self, collection_id: int, properties: list[Property]) -> int:
        with UniqueHelper(self.settings.unique_endpoint) as helper:
            retries = 0

            while retries < Config.MAX_MINER_FORWARD_REQUESTS:
                try:
                    current_nonce = self.get_nft_nonce()

                    time.sleep(0.5 * retries)

                    receipt = helper.execute_extrinsic(
                        self.hotkey,
                        "Unique.create_item",
                        {
                            "collection_id": collection_id,
                            "owner": CrossAccountId(Substrate=self.hotkey.ss58_address),
                            "data": {"NFT": {"properties": [[] if properties is None else properties]}},
                        },
                        sign_params=SignParams(nonce=current_nonce, era=None),
                    )

                    event = helper.find_event("Common.ItemCreated", receipt["events"])
                    if event:
                        collection_id, token_id, owner, collection_type = event["attributes"]
                        self.log.info(f"Successfully minted token {token_id} with nonce {current_nonce}")
                        return token_id
                    else:
                        raise Exception("ItemCreated event not found in receipt")

                except Exception as e:
                    retries += 1
                    error_str = str(e).lower()

                    self.log.warning(
                        f"Error minting token (attempt {retries}/{Config.MAX_MINER_FORWARD_REQUESTS}): {e}"
                    )

                    if any(
                        keyword in error_str
                        for keyword in [
                            "invalid transaction",
                            "priority too low",
                            "transaction is outdated",
                        ]
                    ):
                        self.log.warning(f"Nonce/priority related error detected: {error_str}")
                        wait_time = min(2.0 * retries, 10.0)
                        self.log.info(f"Waiting {wait_time} seconds before retry due to nonce issue")
                        time.sleep(wait_time)

                    elif "insufficient" in error_str and ("balance" in error_str or "funds" in error_str):
                        self.log.error(f"Insufficient balance detected: {e}")
                        raise e

                    elif retries >= Config.MAX_MINER_FORWARD_REQUESTS:
                        self.log.error(f"Failed to mint token after {Config.MAX_MINER_FORWARD_REQUESTS} attempts: {e}")
                        raise e
                    else:
                        time.sleep(0.2 * retries)

            raise Exception(f"Failed to mint token after {Config.MAX_MINER_FORWARD_REQUESTS} attempts")

    def prepare_nft_result(self, reports: list[VulnerabilityReport], task: TaskModel) -> tuple[int, list[int]]:
        token_ids: list[int] = []
        properties = [Property(key="validator", value=task.ss58_address)]

        metadata = NFTMetadata(
            miner_info=MinerInfo(uid=self.uid, ip=self.ip, port=self.port, hotkey=self.hotkey.ss58_address),
            task=task.contract_code if task.ss58_address not in self._callers_whitelist else None,
            audit=reports,
        )

        for block in self.prepare_audit_response(metadata, task):
            token_id = self.mint_token_with_nonce(
                self.collection_id,
                properties
                + [
                    Property(
                        key="audit",
                        value="r_" + block,
                    )
                ],
            )

            token_ids.append(token_id)

        return self.collection_id, token_ids

    def prepare_audit_response(self, metadata: NFTMetadata, task: TaskModel) -> list[str]:
        def split_string(s: str, size: int) -> list[str]:
            return [s[i : i + size] for i in range(0, len(s), size)]

        data = encrypt(metadata.model_dump_json(), self.crypto_hotkey, task.ss58_address)

        self.log.debug(f"Audit report size: {len(data)}")
        if len(data) <= self.MAX_TOKEN_SIZE:
            self.log.info("Audit report is small enough to be sent in one token.")
            return [data]

        self.log.debug("Audit report is too big to be stored in one token.")

        number_of_parts = len(data) // self.MAX_TOKEN_SIZE + 1

        self.log.info(f"Dividing audit report into {number_of_parts} tokens.")

        return list(split_string(data, number_of_parts))

    def do_audit_code(self, task: TaskModel) -> list[VulnerabilityReport]:
        result = requests.post(
            f"{Config.MODEL_SERVER}/submit",
            data=task.contract_code,
            headers={"Content-Type": "text/plain", "X-Validator-Address": task.ss58_address},
            timeout=60 * 3,
        )

        if result.status_code != 200:
            self.log.error(f"Not successful AI response. Description: {result.text}")
            self.log.info("Miner will return an empty response.")
            return []

        reports = result.json()
        self.log.info(f"Response from model server: {reports}")
        vulnerabilities = [
            VulnerabilityReport(
                **vuln,
            )
            for vuln in reports
        ]
        return vulnerabilities

    def check_blacklist(self, request: TaskModel) -> tuple[bool, str | None]:
        if request.ss58_address is None:
            self.log.warning("Received a request without signature.")
            return True, "NoSignature"

        if not request.verify():
            self.log.warning("Received a request with bad signature.")
            return True, "InvalidSignature"

        if request.uid != self.uid:
            self.log.error(
                f"Task is not for this miner. Task uid: {request.uid}, miner uid: {self.uid}, "
                f"validator hotkey: {request.ss58_address}"
            )
            return True, "NotForThisMiner"

        if request.ss58_address not in self._callers_whitelist:
            if (time.time() - self._last_call.get(request.ss58_address, 0)) < self.REQUEST_PERIOD:
                self.log.warning(f"Received a request too often from validator {request.ss58_address}.")
                return True, "TooOften"

        validators = self.relayer_client.get_validators(self.hotkey)
        allowed_keys = list({x.hotkey for x in validators} | set(self._callers_whitelist))
        if request.ss58_address not in allowed_keys:
            self.log.warning("Received a request not from metagraph.")
            return True, "NotValidator"

        self._last_call[request.ss58_address] = time.time()
        return False, None

    def forward(self, task: TaskModel) -> MinerResponseMessage:
        self.check_axon_alive()
        self.log.info(f"Got task from {task.ss58_address}")
        is_blacklisted, error = self.check_blacklist(task)
        if is_blacklisted:
            return MinerResponseMessage(success=False, error=error)

        self.log.info(f"Task is valid, contract code:\n{task.contract_code}")
        max_retries = 5
        retries = 0
        reports = None
        while retries < max_retries:
            retries += 1
            try:
                reports = self.do_audit_code(task)
                break
            except Exception as e:
                self.log.exception(e)
                self.log.error(f"Unable to perform audit: {e}. Retries: {retries}/{max_retries}")

        if reports is None:
            return MinerResponseMessage(success=False, result="Internal error")
        self.log.info(f"Created audit reports: {reports}")
        collection_id, token_ids = self.prepare_nft_result(reports, task)
        self.log.info(f"Tokens minted: {token_ids}")
        response = MinerResponse(
            collection_id=collection_id,
            token_ids=token_ids,
            report=reports,
            uid=task.uid,
        )
        response.sign(self.hotkey)

        return MinerResponseMessage(success=True, result=response)

    def forward_web(self, task: str):
        try:
            result = self.forward(TaskModel(**json.loads(task)))
        except Exception as e:
            self.log.error(f"Exception in forward: {e}")
            result = MinerResponseMessage(success=False, error="MinerInternalError")
        result.sign(self.hotkey)
        return result.model_dump()


def healthchecker():
    return {"status": "OK"}


def miner_version(current_version):
    def endpoint():
        return {"version": current_version}
    return endpoint


def run_miner():
    config = ReinforcedConfig(
        ws_endpoint=Config.CHAIN_ENDPOINT,
        net_uid=Config.NETWORK_UID,
    )
    miner = Miner(config)

    if not miner.wait_for_server(Config.MODEL_SERVER):
        miner.log.error("Miner is not able to connect to model server. Exiting.")
        sys.exit(1)
    miner.serve_axon()
    miner.create_nft_collection()

    server = AxonServer(
        listen_address="0.0.0.0",
        port=Config.BT_AXON_PORT,
        options=AxonServerOptions(max_post_requests=Config.MAX_MINER_FORWARD_REQUESTS),
    )
    server.get("/miner_running", healthchecker)
    server.get("/version", miner_version(miner.code_version()))
    server.post("/forward", miner.forward_web)
    server.run()


if __name__ == "__main__":
    run_miner()
