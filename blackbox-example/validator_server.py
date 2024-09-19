import logging
import random
import time
import asyncio
from fastapi import Body, FastAPI, Query, HTTPException

from unique_subnet.protocol import UniqueSynapse

app = FastAPI()

miners_verifications = {}
execution_events = {}

logger = logging.getLogger("Validator-Server")


@app.post("/validate")
async def validate(uid: int = Query(), result: dict = Body()):
    event = asyncio.Event()
    execution_events[uid] = event

    await asyncio.sleep(5)
    logger.info(f"Body from validator: {result}")
    miners_verifications[uid] = type(result["result"]) == int

    event.set()


@app.get("/get_validation_for_miner")
async def get_validation(uid: int):

    if uid in execution_events:
        await execution_events[uid].wait()
        del execution_events[uid]

    if uid not in miners_verifications:
        raise HTTPException(status_code=404, detail="Miner not found")
    logger.info(
        f"Verification result for miner with UID: {uid} is {miners_verifications[uid]}"
    )
    return miners_verifications[uid]


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="127.0.0.1", port=5001)
