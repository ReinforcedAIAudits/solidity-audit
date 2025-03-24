import json
import os
import time

import fastapi
from substrateinterface import Keypair
from unique_playgrounds import UniqueHelper
from unique_playgrounds.types_unique import CrossAccountId, Property
from unique_playgrounds.unique import NFTToken

from ai_audits.messaging import SignedMessage
from ai_audits.protocol import VulnerabilityReport, ContractTask, ReportMessage
from ai_audits.subnet_utils import create_session
from neurons.base import ReinforcedNeuron, ReinforcedConfig

__all__ = ["Miner"]


class Miner(ReinforcedNeuron):
    NEURON_TYPE = "miner"
    REQUEST_PERIOD = int(os.getenv("MINER_ACCEPT_REQUESTS_EVERY_X_SECS", 20 * 60))
    _last_call: dict[str, float]
    _callers_whitelist: list[str]

    def __init__(self, config: ReinforcedConfig):
        super().__init__(config)
        self._last_call = {}
        self._callers_whitelist = [key.strip() for key in os.getenv("", "").split(",") if key.strip()]
        self.load_website_keys()
        self.set_identity()
        self.collection = self.create_collection()

    def create_collection(self):
        collection = {
            "name": "Miner Contract Audits",
            "description": "Collection of contract audits performed by miner",
            # "token_prefix": "AUD",
            "properties": [
                {"key": "schemaName", "value": "unique"},
                {"key": "schemaVersion", "value": "2.0.0"},
            ],
            "token_property_permissions": [
                {
                    "key": "validator",
                    "permission": {"mutable": False, "token_owner": False, "collection_admin": True},
                },
                {
                    "key": "tokenData",
                    "permission": {"mutable": False, "token_owner": False, "collection_admin": True},
                },
                {
                    "key": "schemaName",
                    "permission": {"mutable": False, "token_owner": False, "collection_admin": True},
                },
                {
                    "key": "schemaVersion",
                    "permission": {"mutable": False, "token_owner": False, "collection_admin": True},
                },
            ],
        }
        with UniqueHelper(self.config.ws_endpoint) as helper:
            collection = helper.nft.create_collection(self.hotkey, collection)

        return collection

    def prepare_nft_result(self, reports: list[VulnerabilityReport], validator_hotkey_ss58: str) -> NFTToken:
        properties = [
            Property(key="validator", value=validator_hotkey_ss58),
            Property(key="tokenData", value=json.dumps([report.model_dump() for report in reports])),
            Property(key="schemaName", value="unique"),
            Property(key="schemaVersion", value="2.0.0"),
        ]

        with UniqueHelper(self.config.ws_endpoint) as helper:
            return helper.nft.mint_token(
                self.hotkey,
                self.collection.collection_id,
                owner=CrossAccountId(Substrate=self.hotkey.ss58_address),
                properties=properties
            )

    def load_website_keys(self):
        try:
            keys_response = create_session().get(os.getenv("KEYS_WEBSITE", "https://audit.reinforced.app/keys"))
            if keys_response.status_code == 200:
                keys_list = keys_response.json()
                if isinstance(keys_list, list) and all(isinstance(key, str) for key in keys_list):
                    self._callers_whitelist = list(set(self._callers_whitelist) | set(keys_list))
                else:
                    self.log.error(f"key list has invalid format: {keys_list}")
            else:
                self.log.info(f"Something went wrong with the key service. Status code: {keys_response.status_code}")
        except Exception as e:
            self.log.error(f"An error occurred while connection to key service: {e}")

    def do_audit_code(self, contract_code: str) -> list[VulnerabilityReport]:
        result = create_session().post(
            f"{os.getenv('MODEL_SERVER')}/submit",
            contract_code,
            headers={"Content-Type": "text/plain"},
        )
        # TODO: Remove the error and allow sending a result with an empty response + log this event
        if result.status_code != 200:
            self.log.info(f"Not successful AI response. Description: {result.text}")
            raise ValueError("Contract audit is not successful!")

        json = result.json()
        self.log.info(f"Response from model server: {json}")
        vulnerabilities = [
            VulnerabilityReport(
                **vuln,
            )
            for vuln in json
        ]
        return vulnerabilities

    def check_blacklist(self, request: SignedMessage) -> tuple[bool, dict | None]:
        if request.ss58_address is None:
            self.log.warning("Received a request without signature.")
            return True, {"name": "NoSignature"}

        if not request.verify():
            self.log.warning("Received a request with bad signature.")
            return True, {"name": "InvalidSignature"}

        if (
            request.ss58_address in self._last_call
            and time.time() - self._last_call[request.ss58_address] < self.REQUEST_PERIOD
        ):
            self.log.warning("Received a request too often.")
            return True, {"name": "TooOften"}

        axons = self.get_axons()
        # TODO: check relayer and validators and site
        allowed_keys = list(set([x["hotkey"] for x in axons]) | set(self._callers_whitelist))
        if request.ss58_address not in allowed_keys:
            self.log.warning("Received a request not from metagraph.")
            return True, {"name": "NotFromMetagraph"}

        for axon in axons:
            if request.ss58_address == axon["hotkey"] and axon["rank"] != 0:
                self.log.warning("Received a request from not a validator.")
                return True, {"name": "NotValidator"}

        self._last_call[request.ss58_address] = time.time()
        return False, None

    def forward(self, task: ContractTask):
        self.check_axon_alive()
        self.log.info(f"Got task from {task.ss58_address}")
        is_blacklisted, error = self.check_blacklist(task)
        if is_blacklisted:
            return {"status": "ERROR", "reason": error}

        if task.uid != self.uid:
            self.log.error(f"Task is not for this miner. Task uid: {task.uid}, miner uid: {self.uid}")
            return {"status": "ERROR", "reason": "Task is not for this miner"}

        self.log.info(f"Task is valid, contract code:\n{task.contract_code}")
        reports = self.do_audit_code(task.contract_code)
        self.log.info(f"Created audit reports: {reports}")
        nft_token = self.prepare_nft_result(reports, task.ss58_address)
        self.log.info(f"Token minted: {nft_token}")
        message = ReportMessage(
            collection_id=self.collection.collection_id,
            token_id=nft_token.token_id,
            report=reports,
        )
        message.sign(Keypair(ss58_address=self.hotkey.ss58_address))

        return message


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
    # TODO: unwrap relayer here
    result = miner.forward(task)
    return result


if __name__ == "__main__":
    miner.serve_axon()
    miner.serve_uvicorn(app)
