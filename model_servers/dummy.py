import json
import hashlib
import logging
import os
import time
import random
import re

import dotenv
from fastapi import FastAPI, Request

from ai_audits.protocol import VulnerabilityReport

app = FastAPI()

logger = logging.getLogger("MinerBlackbox")

dotenv.load_dotenv()


class TemplatesSingleton:
    TEMPLATE_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "tests", "examples")
    )

    def __init__(self):
        self._cache = None
        self._templates = self.load_template_names()

    @property
    def cache(self):
        if self._cache is None:
            self.load_cache()
        return self._cache

    def load_template_names(self):
        return [
            x
            for x in os.listdir(os.path.join(self.TEMPLATE_DIR, "tasks"))
            if x.endswith(".json")
        ]

    def load_task(self, file_name: str):
        if file_name not in self._templates:
            file_name = random.choice(self._templates)
        with open(
            os.path.join(self.TEMPLATE_DIR, "tasks", file_name), "r", encoding="utf-8"
        ) as f:
            return json.loads(f.read())

    def load_response(self, file_name: str):
        if file_name not in self._templates:
            file_name = random.choice(self._templates)
        with open(
            os.path.join(self.TEMPLATE_DIR, "responses", file_name),
            "r",
            encoding="utf-8",
        ) as f:
            return json.loads(f.read())

    @classmethod
    def make_hash(cls, code: str):
        return hashlib.md5(code.encode()).hexdigest()

    def load_cache(self):
        templates = self._templates
        self._cache = {
            self.make_hash(self.load_task(x)["contractCode"]): self.load_response(x)
            for x in templates
        }

    def get_response(self, code: str):
        code_hash = self.make_hash(code)
        return self.cache.get(
            code_hash,
            [
                {
                    "fromLine": 1,
                    "toLine": len(code.splitlines()),
                    "vulnerabilityClass": "Invalid Code",
                    "description": "The entire code is considered invalid for audit processing.",
                }
            ],
        )

    def get_task(self, vulnerability: str | None = None):
        if vulnerability is not None:
            file_name = re.sub("[^aA-zZ]", "_", vulnerability.lower())
            file_name = f"{file_name}.json"
        else:
            file_name = random.choice(self._templates)
        return self.load_task(file_name)


dummy_contracts = TemplatesSingleton()


@app.post("/submit")
async def contract_report(request: Request):
    solidity = (await request.body()).decode("utf-8")
    logger.info(f"Received solidity: {solidity}")

    time.sleep(random.randint(1_000, 4_000) / 1_000)

    response = [
        VulnerabilityReport(**x) for x in dummy_contracts.get_response(solidity)
    ]

    logger.info(f"Sending response: {response}")
    return response


@app.post("/task")
@app.post("/hybrid_task")
async def task_provider(request: Request):
    requested_vulnerability = (await request.body()).decode("utf-8")
    logger.info(f"Requested vulnerability: {requested_vulnerability}")
    return dummy_contracts.get_task(requested_vulnerability)


@app.get("/healthcheck")
async def healthchecker():
    return {"status": "OK"}


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5009")))
