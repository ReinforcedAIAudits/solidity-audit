import json
import os
import random

from fastapi import FastAPI, Request, HTTPException
from openai import AsyncOpenAI
from pydantic import BaseModel
from py_solidity_vuln_db import get_vulnerability

from ai_audits.contracts.contract_generator import (
    Vulnerability,
    create_contract,
    create_task,
    extract_storages_functions,
)
from ai_audits.protocol import SmartContract, ValidatorTask, KnownVulnerability
from ai_audits.subnet_utils import ROLES, SolcSingleton, preprocess_text


GPT_MODEL = "meta-llama/llama-3.3-70b-instruct"

client = AsyncOpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPEN_ROUTER_API_KEY"),
)
app = FastAPI()


VULNERABILITIES_TO_GENERATE = [
    KnownVulnerability.REENTRANCY.value,
    KnownVulnerability.GAS_GRIEFING.value,
    KnownVulnerability.BAD_RANDOMNESS.value,
    KnownVulnerability.FORCED_RECEPTION.value,
    KnownVulnerability.UNGUARDED_FUNCTION.value,
    KnownVulnerability.SIGNATURE_REPLAY.value,
]


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
        "isSuggestion": "Boolean value indicating if the fix is a suggestion or a requirement"
    }
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


PROMPT_VALIDATOR = """
You are a Solidity smart contract auditor. 
Your role is to help user auditors learn about Solidity vulnerabilities by providing them with vulnerable contracts.
Be creative when generating contracts, avoid using common names or known contract structures. 
Do not include comments describing the vulnerabilities in the code, human auditors should identify them on their own.

Aim to create more complex contracts rather than simple, typical examples. 
Each contract should include 3-5 state variables and 3-5 functions, with at least one function MUST containing a vulnerability. 
Ensure that the contract code is valid and can be successfully compiled.

Generate response in JSON format with no extra comments or explanations. 
Answer with only JSON, without markdown formatting.

Output format:
{
    "fromLine": "Start line of the vulnerability", 
    "toLine": "End line of the vulnerability",
    "vulnerabilityClass": "Type of vulnerability (e.g., Reentrancy, Integer Overflow)",
    "contractCode": "Code of vulnerable contract"
}
""".strip()


def get_hybrid_validator_prompt(functions: list[str], storages: list[str]) -> str:
    return f"""
You are a Solidity smart contract writer. 
Your role is to help user writers learn Solidity smart contracts by providing them different examples of contracts.
Be creative when generating contracts, avoid using common names or known contract structures. 
Do not use primitive examples of contracts, human writers need to understand the complexity of the contracts.

Aim to create more complex contracts rather than simple, typical examples. 
Each contract must include {functions} functions, {storages} storages and more 2-3 state variables and 2-3 functions. 
Ensure that the contract code is valid and can be successfully compiled by solidity compiler.

Generate response in JSON format with no extra comments or explanations.
Answer with only JSON text, without markdown formatting, without any formatting.

Output format:
{{
    "code": "Solidity code of the contract"
}}
""".strip()


solc = SolcSingleton()


async def generate_contract(functions: list[str], storages: list[str]) -> SmartContract | None:
    completion = await client.chat.completions.create(
        model=os.getenv("OPEN_ROUTER_MODEL", GPT_MODEL),
        messages=[
            {"role": ROLES.SYSTEM, "content": get_hybrid_validator_prompt(functions, storages)},
            {
                "role": ROLES.USER,
                "content": f"Generate new valid smart contract",
            },
        ],
        temperature=0.3,
    )
    return try_prepare_contract(completion.choices[0].message.content)


REQUIRED_KEYS = {"fromLine", "toLine", "vulnerabilityClass"}
INT_KEYS = {"fromLine", "toLine"}
STR_EXTRA_KEYS = {"description", "fixedLines", "testCase"}


def try_prepare_contract(result) -> SmartContract | None:
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except:
            return None
    if not isinstance(result, dict):
        return None
    if "code" not in result:
        return None
    return SmartContract(code=result["code"])


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
            if isinstance(cleared[k], int) or (isinstance(item[k], str) and item[k].isdigit()):
                cleared[k] = int(cleared[k])
            else:
                return None
        prepared.append(cleared)
    return prepared


async def generate_audit(source: str):
    """
    Here goes the magic.
    Reference implementation simply feeds all the data to LLM and hopes something good comes out.

    Good implementation should have good preprocessing, response augmentation for LLM to provide good prior art
    descriptions, it may call external linters to provide some initial guidance to LLM, etc.
    It also needs to verify the output, as LLM might hallucinate and produce invalid line ranges
    and other sorts of undesired output.
    """
    preprocessed = preprocess_text(source)
    completion = await client.chat.completions.create(
        model=os.getenv("OPEN_ROUTER_MODEL", GPT_MODEL),
        messages=[
            {
                "role": ROLES.SYSTEM,
                "content": PROMPT,
            },
            {"role": ROLES.USER, "content": preprocessed},
        ],
    )

    return completion.choices[0].message.content


@app.post("/submit")
async def submit(request: Request):
    contract_code = (await request.body()).decode("utf-8")
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None
    while tries > 0:
        result = await generate_audit(contract_code)
        result = try_prepare_audit_result(result)
        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid answer from LLM")
    return result


class ContractInfo(BaseModel):
    functions: list[str]
    storages: list[str]


@app.post("/valid_contract")
async def get_valid_contract(request: Request, contract_info: ContractInfo):
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None

    while tries > 0:
        result = await generate_contract(
            contract_info.functions,
            contract_info.storages,
        )
        print(f"Generated contract: {result}")
        try:
            solc.compile(result.code)
        except Exception as e:
            print(f"Compilation error: {e}")
            continue

        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid answer from LLM")

    return result.code


async def generate_task(requested_vulnerability: str | None = None) -> ValidatorTask:
    possible_vulnerabilities = (
        random.sample(VULNERABILITIES_TO_GENERATE, min(3, len(VULNERABILITIES_TO_GENERATE)))
        if requested_vulnerability is None
        else [requested_vulnerability]
    )
    completion = await client.beta.chat.completions.parse(
        model=os.getenv("OPEN_ROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct"),
        messages=[
            {"role": ROLES.SYSTEM, "content": PROMPT_VALIDATOR},
            # Output format guidance is provided automatically by OpenAI SDK.
            {
                "role": ROLES.USER,
                "content": f"Generate new vulnerable contract with one of "
                f"vulnerabilities: {', '.join(possible_vulnerabilities)}",
            },
        ],
        response_format=ValidatorTask,
        temperature=0.3,
    )
    message = completion.choices[0].message
    if message.parsed:
        return message.parsed
    else:
        return None


@app.post("/task", response_model=ValidatorTask)
async def get_task(request: Request):
    requested_vulnerability = (await request.body()).decode("utf-8")
    if requested_vulnerability not in VULNERABILITIES_TO_GENERATE:
        requested_vulnerability = None
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, validator_template = False, None
    while tries > 0:
        tries -= 1
        validator_template = await generate_task(requested_vulnerability)
        if validator_template is None:
            continue
        try:
            solc.compile(validator_template.contract_code)
        except:
            continue
        if validator_template is not None:
            is_valid = True
            break
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid answer from LLM")
    return validator_template


@app.post("/hybrid_task")
async def get_hybrid_task(request: Request):
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None

    requested_vulnerability = (await request.body()).decode("utf-8")
    if requested_vulnerability not in VULNERABILITIES_TO_GENERATE:
        requested_vulnerability = None

    raw_vulnerability = get_vulnerability(requested_vulnerability.lower() if requested_vulnerability else None)
    raw_vulnerability = Vulnerability(vulnerabilityClass=raw_vulnerability.name, code=raw_vulnerability.code)

    while tries > 0:
        tries -= 1
        vulnerability_contract = create_contract(raw_vulnerability.code)
        storages, functions = extract_storages_functions(vulnerability_contract)
        result = await generate_contract(storages, functions)

        print(f"Generated contract: {result}")
        try:
            solc.compile(result.code)
        except Exception as e:
            print(f"Compilation error: {e}")
            continue

        if result is not None:
            is_valid = True
            break
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid answer from LLM")

    return create_task(result.code, raw_vulnerability)


@app.get("/healthcheck")
async def healthchecker():
    return {"status": "OK"}


if __name__ == "__main__":
    import uvicorn

    solc.install_solc()
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5000")))
