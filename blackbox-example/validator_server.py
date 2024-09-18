import random
import time
import asyncio
from fastapi import Body, FastAPI, Query, HTTPException

from unique_subnet.protocol import UniqueSynapse

app = FastAPI()

miners_synapses = {}
execution_events = {}


@app.post("/validate")
async def validate(uid: int = Query(), synapse: UniqueSynapse = Body()):
    event = asyncio.Event()
    execution_events[uid] = event

    await asyncio.sleep(5)
    miners_synapses[uid] = type(synapse.response) == int

    event.set()


@app.get("/get_validation_for_miner")
async def get_validation(uid: int):

    if uid in execution_events:
        await execution_events[uid].wait()
        del execution_events[uid]

    if uid not in miners_synapses:
        raise HTTPException(status_code=404, detail="Miner not found")

    return miners_synapses[uid]

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5001)
