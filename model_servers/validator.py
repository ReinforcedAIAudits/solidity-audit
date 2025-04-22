import json
import os
import random

from fastapi import FastAPI, Request, HTTPException
from openai import AsyncOpenAI
from py_solidity_vuln_db import get_vulnerability
from solc_ast_parser.utils import compile_contract_with_standart_input

from ai_audits.contracts.contract_generator import (
    Vulnerability,
    create_contract,
    create_task,
)
from ai_audits.protocol import SmartContract, ValidatorTask, KnownVulnerability, TaskType
from ai_audits.subnet_utils import ROLES, SolcSingleton

GPT_MODEL = "anthropic/claude-3.7-sonnet"

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

PROMPT_VALID_CONTRACT = """
    You are a Solidity smart contract writer. 
    Your role is to help user writers learn Solidity smart contracts by providing them different examples of contracts.
    Be creative when generating contracts, avoid using common names or known contract structures. 
    Do not use primitive examples of contracts, human writers need to understand the complexity of the contracts.

    Aim to create more complex contracts rather than simple, typical examples.  
    You should add 5-7 state variables and 5-7 functions.
    Ensure that the contract code is valid and can be successfully compiled by solidity compiler.

    Generate response in JSON format with no extra comments or explanations.
    Answer with only JSON text, without markdown formatting, without any formatting.

    Output format:
    {{
        "code": "Solidity code of the contract"
    }}
"""


def get_hybrid_validator_prompt(code: str) -> str:
    return f"""
    You are a Solidity smart contract writer. 
    Your role is to help user writers learn Solidity smart contracts by providing them different examples of contracts.
    Be creative when generating contracts, avoid using common names or known contract structures. 
    Do not use primitive examples of contracts, human writers need to understand the complexity of the contracts.

    Aim to create more complex contracts rather than simple, typical examples. 
    You need to analyze this code: {code}
    and define or initialize all identifiers that are presented in this code, 
    except builtin functions and storages. (note: you are not allowed to use any imports and library initialization). 
    Also you should add 2-3 state variables and 2-3 functions.
    Ensure that the contract code is valid, doesn't include any undeclared identifiers and can be successfully compiled by solidity compiler.

    Generate response in JSON format with no extra comments or explanations.
    Answer with only JSON text, without markdown formatting, without any formatting.

    Output format:
    {{
        "code": "Solidity code of the contract"
    }}
    """.strip()


solc = SolcSingleton()


async def generate_contract(prompt: str) -> SmartContract | None:
    completion = await client.chat.completions.create(
        model=GPT_MODEL,
        messages=[
            {"role": ROLES.SYSTEM, "content": prompt},
            {
                "role": ROLES.USER,
                "content": f"Generate new valid smart contract",
            },
        ],
        temperature=0.3,
    )
    return try_prepare_contract(completion.choices[0].message.content)


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


async def generate_task(requested_vulnerability: str | None = None) -> ValidatorTask:
    possible_vulnerabilities = (
        random.sample(VULNERABILITIES_TO_GENERATE, min(3, len(VULNERABILITIES_TO_GENERATE)))
        if requested_vulnerability is None
        else [requested_vulnerability]
    )
    completion = await client.beta.chat.completions.parse(
        model=GPT_MODEL,
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

    while tries > 0:
        raw_vulnerability = get_vulnerability(requested_vulnerability.lower() if requested_vulnerability else None)
        print(f"Raw vulnerability code: {repr(raw_vulnerability.code)}")
        raw_vulnerability = Vulnerability(vulnerabilityClass=raw_vulnerability.name, code=raw_vulnerability.code)

        tries -= 1
        try:
            compile_contract_with_standart_input(create_contract(raw_vulnerability.code))
        except Exception as e:
            print(f"Vulnerability compilation error: {e}")
            continue

        result = await generate_contract(get_hybrid_validator_prompt(raw_vulnerability.code))
        print(f"Generated contract: {repr(result)}")

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

    try:
        task = create_task(result.code, raw_vulnerability)
        print(f"Task code: {repr(task.contract_code)}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return task


@app.post("/valid_contract")
async def get_valid_contract(request: Request):
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None


    while tries > 0:
        result = await generate_contract(prompt=PROMPT_VALID_CONTRACT)

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

    return ValidatorTask(
        contract_code=result.code,
        task_type=TaskType.VALID_CONTRACT,
        from_line=1,
        to_line=len(result.code.splitlines()) + 1,
        vulnerability_class="Valid contract",
    )


@app.get("/healthcheck")
async def healthchecker():
    return {"status": "OK"}


if __name__ == "__main__":
    import uvicorn

    solc.install_solc()
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5000")))
