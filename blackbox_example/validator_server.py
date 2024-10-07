import logging

import os
import random
import time
from typing import List
from types import SimpleNamespace

import dotenv
from fastapi import Body, FastAPI, HTTPException

from ai_audits.protocol import VulnerabilityReport
from ai_audits.contract_provider import FileContractProvdier

CONTRACT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "contract_templates"
)

PROVIDER = FileContractProvdier(CONTRACT_DIR)
app = FastAPI()

miners_verifications = {}
execution_events = {}

logger = logging.getLogger("AuditValidatorBlackbox")
dotenv.load_dotenv()

@app.get("/generate_contract")
async def generate_contract():

    pair = PROVIDER.get_random_pair()
    logger.info(f"Generated pair: {pair}")
    # TODO: fix it in the future
    return pair


@app.post("/validate")
async def validate(vulnerability_report: List[VulnerabilityReport] = Body()):
    for report in vulnerability_report:
        if report.from_line != 12 or report.to_line != 19:
            logger.info("Incorrect location information for report: %s", report)
            return {"result": 0.0}

    return {"result": 1.0}


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, port=os.getenv("VALIDATOR_PORT"))
