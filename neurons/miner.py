import os
import time

import fastapi
from solidity_audit_lib.messaging import VulnerabilityReport, ContractTask

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

    def check_blacklist(self, request: ContractTask) -> tuple[bool, dict | None]:
        if request.ss58_address is None:
            self.log.warning("Received a request without signature.")
            return True, {"name": "NoSignature"}

        if not request.verify():
            self.log.warning("Received a request with bad signature.")
            return True, {"name": "InvalidSignature"}

        if request.uid != self.uid:
            self.log.error(f"Task is not for this miner. Task uid: {request.uid}, miner uid: {self.uid}")
            return True, {"name": "NotForThisMiner"}

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

        self.log.info(f"Task is valid, contract code:\n{task.contract_code}")
        return self.do_audit_code(task.contract_code)


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
