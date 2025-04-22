import os
import time

import atomics
import fastapi
from solidity_audit_lib.encrypting import encrypt
from solidity_audit_lib.messaging import VulnerabilityReport, ContractTask, MinerResponseMessage, MinerResponse
from solidity_audit_lib.relayer_client.relayer_types import MinerStorage
from unique_playgrounds import UniqueHelper
from unique_playgrounds.types_system import SignParams
from unique_playgrounds.types_unique import CrossAccountId, Property

from ai_audits.protocol import MinerInfo, NFTMetadata
from ai_audits.subnet_utils import create_session
from neurons.base import ReinforcedNeuron, ReinforcedConfig

__all__ = ["Miner"]


class Miner(ReinforcedNeuron):
    NEURON_TYPE = "miner"
    REQUEST_PERIOD = int(os.getenv("MINER_ACCEPT_REQUESTS_EVERY_X_SECS", 20 * 60))
    MAX_TOKEN_SIZE = 1024 * 31
    _last_call: dict[str, float]
    _callers_whitelist: list[str]

    def __init__(self, config: ReinforcedConfig):
        super().__init__(config)
        self._last_call = {}
        self._callers_whitelist = list(
            set(self.settings.trusted_keys)
            | {key.strip() for key in os.getenv("WHITELISTED_KEYS", "").split(",") if key.strip()}
        )
        self.collection_id = None
        self.nonce = atomics.atomic(width=4, atype=atomics.INT)
        self.nonce.add(self.get_nft_nonce())

    def create_nft_collection(self) -> int:
        existed = self.relayer_client.get_storage(self.hotkey)
        if existed.success and existed.result is not None and "collection_id" in existed.result:
            if self.check_nft_collection_ownership(existed.result["collection_id"], self.hotkey.ss58_address):
                self.collection_id = existed.result["collection_id"]
                self.log.info(f"Collection #{self.collection_id} found for {self.hotkey.ss58_address}")
                return self.collection_id
        collection_data = {
            "name": f"Miner {self.hotkey.ss58_address[:4]}...{self.hotkey.ss58_address[-4:]} "
                    f"audits ({os.getenv('NETWORK_TYPE', 'mainnet')})",
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
            collection = helper.nft.create_collection(self.hotkey, collection_data)
            collection_id = collection.collection_id
            self.nonce.inc()

        self.relayer_client.set_storage(self.hotkey, MinerStorage(collection_id=collection_id))

        self.collection_id = collection_id
        self.log.info(f"Created collection #{self.collection_id} for {self.hotkey.ss58_address}")
        return self.collection_id

    async def mint_token_with_nonce(self, collection_id: int, properties: list[Property]) -> int:
        with UniqueHelper(self.settings.unique_endpoint) as helper:
            current_nonce = self.nonce.fetch_inc()
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

        collection_id, token_id, owner, collection_type = event["attributes"]
        return token_id

    async def prepare_nft_result(self, reports: list[VulnerabilityReport], task: ContractTask) -> tuple[int, list[int]]:
        token_ids: list[int] = []
        properties = [Property(key="validator", value=task.ss58_address)]

        metadata = NFTMetadata(
            miner_info=MinerInfo(uid=self.uid, ip=self.ip, port=self.port, hotkey=self.hotkey.ss58_address),
            task=task.contract_code,
            audit=reports,
        )

        for block in self.prepare_audit_response(metadata):
            metadata.audit = block
            token_id = await self.mint_token_with_nonce(
                self.collection_id,
                properties
                + [Property(key="audit", value="r_" + encrypt(metadata.model_dump_json(), self.crypto_hotkey, task.ss58_address))]
            )

            token_ids.append(token_id)

        return self.collection_id, token_ids

    def prepare_audit_response(self, metadata: NFTMetadata) -> list[list[VulnerabilityReport]]:
        def split_list(array: list, parts: int):
            k, m = divmod(len(array), parts)
            return (array[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(parts))

        data = encrypt(
            metadata.model_dump_json(),
            self.crypto_hotkey,
            self.hotkey.ss58_address,
        )

        self.log.debug(f"Audit report size: {len(data)}")
        if len(data) <= self.MAX_TOKEN_SIZE:
            self.log.info("Audit report is small enough to be sent in one token.")
            return [metadata.audit]

        self.log.debug("Audit report is too big to be stored in one token.")

        number_of_parts = len(data) // self.MAX_TOKEN_SIZE + 1

        self.log.info(f"Dividing audit report into {number_of_parts} tokens.")

        return list(split_list(metadata.audit, number_of_parts))

    def do_audit_code(self, task: ContractTask) -> list[VulnerabilityReport]:
        result = create_session().post(
            f"{os.getenv('MODEL_SERVER')}/submit",
            task.contract_code,
            headers={"Content-Type": "text/plain", "X-Validator-Address": task.ss58_address},
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

    def check_blacklist(self, request: ContractTask) -> tuple[bool, str | None]:
        if request.ss58_address is None:
            self.log.warning("Received a request without signature.")
            return True, "NoSignature"

        if not request.verify():
            self.log.warning("Received a request with bad signature.")
            return True, "InvalidSignature"

        if request.uid != self.uid:
            self.log.error(f"Task is not for this miner. Task uid: {request.uid}, miner uid: {self.uid}")
            return True, "NotForThisMiner"

        if (
            request.ss58_address in self._last_call
            and request.ss58_address not in self._callers_whitelist
            and time.time() - self._last_call[request.ss58_address] < self.REQUEST_PERIOD
        ):
            self.log.warning("Received a request too often.")
            return True, "TooOften"

        axons = self.get_axons()
        allowed_keys = list(set([x["hotkey"] for x in axons]) | set(self._callers_whitelist))
        if request.ss58_address not in allowed_keys:
            self.log.warning("Received a request not from metagraph.")
            return True, "NotFromMetagraph"

        for axon in axons:
            if request.ss58_address == axon["hotkey"] and axon["rank"] != 0:
                self.log.warning("Received a request from not a validator.")
                return True, "NotValidator"

        self._last_call[request.ss58_address] = time.time()
        return False, None

    async def forward(self, task: ContractTask) -> MinerResponseMessage:
        self.check_axon_alive()
        self.log.info(f"Got task from {task.ss58_address}")
        is_blacklisted, error = self.check_blacklist(task)
        if is_blacklisted:
            return MinerResponseMessage(success=False, error=error)

        self.log.info(f"Task is valid, contract code:\n{task.contract_code}")
        reports = self.do_audit_code(task)
        self.log.info(f"Created audit reports: {reports}")
        collection_id, token_ids = await self.prepare_nft_result(reports, task)
        self.log.info(f"Tokens minted: {token_ids}")
        response = MinerResponse(
            collection_id=collection_id,
            token_ids=token_ids,
            report=reports,
            uid=task.uid,
        )
        response.sign(self.hotkey)

        return MinerResponseMessage(success=True, result=response)


app = fastapi.FastAPI()

config = ReinforcedConfig(
    ws_endpoint=os.getenv("CHAIN_ENDPOINT", "wss://test.finney.opentensor.ai:443"),
    net_uid=int(os.getenv("NETWORK_UID", "222")),
)
miner = Miner(config)


@app.get("/miner_running")
async def healthchecker():
    return {"status": "OK"}


@app.post("/forward")
async def forward(task: ContractTask):
    try:
        result = await miner.forward(task)
    except Exception as e:
        miner.log.error(f"Exception in forward: {e}")
        result = MinerResponseMessage(success=False, error="MinerInternalError")
    result.sign(miner.hotkey)
    return result.model_dump()


if __name__ == "__main__":
    if not miner.wait_for_server(os.getenv("MODEL_SERVER", "http://localhost:5000")):
        miner.log.error("Miner is not able to connect to model server. Exiting.")
        exit(1)

    miner.serve_axon()
    miner.create_nft_collection()
    miner.serve_uvicorn(app)
