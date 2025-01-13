import datetime
import json
import os
import random
import time
from typing import List

from fastapi import FastAPI, Request, HTTPException
from openai import AsyncOpenAI
from pydantic import BaseModel

from ai_audits.protocol import SmartContract
from ai_audits.subnet_utils import create_session, preprocess_text, ROLES, SolcSingleton


client = AsyncOpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPEN_ROUTER_API_KEY"),
)
app = FastAPI()


PROMPT = """
You are an auditor reviewing smart contract source code. 
Given code with line numbers, generate an audit report in JSON format with no extra comments or explanations.

Output format:
[
    {
        "fromLine": "Start line of the vulnerability", 
        "toLine": "End line of the vulnerability",
        "vulnerabilityClass": "Type of vulnerability (e.g., Reentrancy, Integer Overflow)",
        "testCase": "Example code that could trigger the vulnerability",
        "description": "Detailed description of the issue",
        "priorArt": "Similar vulnerabilities encountered in wild before. Type: array",
        "fixedLines": "Fixed version of the original source",
    },
]

If the entire code is invalid or cannot be meaningfully analyzed:
- Generate a single vulnerability report entry with the following details:
    {
        "fromLine": 1, 
        "toLine": Total number of lines in the code,
        "vulnerabilityClass": "Invalid Code",
        "description": "The entire code is considered invalid for audit processing.",
    }

For fields `fromLine` and `toLine` use only the line number as an integer, without any prefix.
Each report entry should describe a separate vulnerability with precise line numbers, type, and an exploit example. 
The generated audit report should not contain any extra comments or explanations.
""".strip()

def get_prompt(functions: List[str], storages: List[str]) -> str:
    return f"""
You are a Solidity smart contract writer. 
Your role is to help user writers learn Solidity smart contracts by providing them different examples of contracts.
Be creative when generating contracts, avoid using common names or known contract structures. 
Do not use primritive examples of contracts, human writers need to understand the complexity of the contracts.

Aim to create more complex contracts rather than simple, typical examples. 
Each contract must include {functions} functions, {storages} storages and more 2-3 state variables and 2-3 functions. 
Ensure that the contract code is valid and can be successfully compiled.

Generate response in JSON format with no extra comments or explanations.
Answer with only JSON text, without markdown formatting.

Output format:
{{
    "code": "Solidity code of the contract"
}}
""".strip()

solc = SolcSingleton()


async def generate_contract(functions: List[str], storages: List[str]) -> SmartContract:

    completion = await client.beta.chat.completions.parse(
        model=os.getenv("OPEN_ROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct"),
        messages=[
            {"role": ROLES.SYSTEM, "content": get_prompt(functions, storages)},
            # Output format guidance is provided automatically by OpenAI SDK.
            {
                "role": ROLES.USER,
                "content": f"Generate new valid smart contract",
            },
        ],
        response_format=SmartContract,
        temperature=0.3,
    )

    if completion.choices[0].message.parsed:
        return completion.choices[0].message.parsed
    else:
        return None


REQUIRED_KEYS = {"fromLine", "toLine", "vulnerabilityClass"}
INT_KEYS = {"fromLine", "toLine"}
STR_EXTRA_KEYS = {"description", "fixedLines", "testCase"}


def try_prepare_audit_result(result) -> list[dict] | None:
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except:
            return None
    if isinstance(result, dict):
        result = [result]
    prepared = []
    for item in result:
        for key in REQUIRED_KEYS:
            if key not in item:
                return None
        cleared = {k: item[k] for k in REQUIRED_KEYS}
        if (
            "priorArt" in item
            and isinstance(item["priorArt"], list)
            and all(isinstance(x, str) for x in item["priorArt"])
        ):
            cleared["priorArt"] = item["priorArt"]
        for key in STR_EXTRA_KEYS:
            if isinstance(item.get(key, None), str):
                cleared[key] = item[key]
        for k in INT_KEYS:
            if isinstance(cleared[k], int) or (
                isinstance(item[k], str) and item[k].isdigit()
            ):
                cleared[k] = int(cleared[k])
            else:
                return None
        prepared.append(cleared)
    return prepared


@app.post("/submit")
async def submit(request: Request):
    contract_code = (await request.body()).decode("utf-8")
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None
    while tries > 0:
        result = generate_audit(contract_code)
        result = try_prepare_audit_result(result)
        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid answer from LLM")
    return result


class ContractInfo(BaseModel):
    functions: List[str]
    storages: List[str]


@app.post("/task")
async def get_task(request: Request, contract_info: ContractInfo):
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None
    while tries > 0:
        result = await generate_contract(contract_info.functions, contract_info.storages)
        print(f"Generated contract: {result}")
        try:
            solc.compile(result.code)
        except:
            continue

        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid answer from LLM")
    
    with open(f"contracts_from_llm/{datetime.datetime.now()}.sol", "w+") as f:
        f.write(result.code)
    return result


@app.get("/healthcheck")
async def healthchecker():
    return {"status": "OK"}


if __name__ == "__main__":
    import uvicorn

    solc.install_solc()
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5000")))
