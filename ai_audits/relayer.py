import time
from typing import List
import aiohttp
from bt_decode import AxonInfo, NeuronInfo
from fastapi import FastAPI

from ai_audits.protocol import ResultMessage, TaskMessage, VulnerabilityReport, ReportMessage


app = FastAPI()


async def get_miners() -> List[NeuronInfo]:
    # TODO get miner addresses from site
    pass


@app.post("/forward")
async def forward(task: TaskMessage):
    if not task.code.verify() or not task.code.ss58_address != task.validator_ss58_hotkey:
        raise ValueError("Invalid task message")

    async with aiohttp.ClientSession() as session:
        for miner in await get_miners():

            start_time = time.time()
            response = await session.post(
                f"https://{miner.axon_info.ip}:{miner.axon_info.port}/forward", json=task.model_dump()
            )
            end_time = time.time()

            result_message = [VulnerabilityReport(**vuln) for vuln in await response.json()]
            report = ReportMessage(report=result_message)
            report.sign(miner.coldkey)

            return ResultMessage(
                result=report, miner_ss58_hotkey=miner.hotkey.ss58_address, response_time=end_time - start_time
            )
