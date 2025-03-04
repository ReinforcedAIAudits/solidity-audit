import os
import random

from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel
from openai import AsyncOpenAI
from py_solidity_vuln_db import get_vulnerability
from solc_ast_parser.models.base_ast_models import NodeType
from solc_ast_parser.ast_parser import build_function_header, parse_variable_declaration

from ai_audits.contracts.contract_generator import (
    Vulnerability,
    create_contract,
    create_task,
    get_contract_nodes_from_source,
    prepare_vulnerability,
)
from ai_audits.protocol import VulnerabilityReport, ValidatorTask, KnownVulnerability, SmartContract
from ai_audits.subnet_utils import preprocess_text, ROLES, SolcSingleton


# OpenAI wants response top-level entity to be an object.
class AuditResponse(BaseModel):
    result: list[VulnerabilityReport]


solc = SolcSingleton()

client = AsyncOpenAI(
    base_url=os.getenv("OPENAI_API_URL", "https://api.openai.com"),
)
app = FastAPI()


GPT_MODEL = os.getenv("GPT_MODEL", "gpt-4o-mini-2024-07-18")


PROMPT = """
You are a Solidity smart contract auditor. 
Given the source code of a contract with explicitly specified line numbers in comments, your task is to provide an audit report.

- If the source code is not valid Solidity code (only if it cannot be compiled), generate a single vulnerability report entry with the following details:
 - from_line: 1 (start of the code)
 - to_line: the total number of lines in the code
 - vulnerability_class: "Invalid Code"
 - description: A message indicating that the entire code is considered invalid for audit processing.
- If the source code is valid, analyze and report specific vulnerabilities, providing:
 - The line range (from_line and to_line) of each vulnerability.
 - A brief description of the vulnerability.
 - Suggestions for fixes.
- If no vulnerabilities are found in the source code, generate an audit report without any entries.
""".strip()

PROMPT_VALIDATOR = """
You are a Solidity smart contract auditor. 
Your role is to help user auditors learn about Solidity vulnerabilities by providing them with vulnerable contracts.
Be creative when generating contracts, avoid using common names or known contract structures. 
Do not include comments describing the vulnerabilities in the code, human auditors should identify them on their own.

Aim to create more complex contracts rather than simple, typical examples. 
Each contract should include 3-5 state variables and 3-5 functions, with at least one function MUST containing a vulnerability. 
Ensure that the contract code is valid and can be successfully compiled.
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
""".strip()


VULNERABILITIES_TO_GENERATE = [
    KnownVulnerability.REENTRANCY.value,
    KnownVulnerability.GAS_GRIEFING.value,
    KnownVulnerability.BAD_RANDOMNESS.value,
    KnownVulnerability.FORCED_RECEPTION.value,
    KnownVulnerability.UNGUARDED_FUNCTION.value,
    KnownVulnerability.SIGNATURE_REPLAY.value,
    KnownVulnerability.UNSAFE_OPERATION.value,
]


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
    completion = await client.beta.chat.completions.parse(
        model=GPT_MODEL,
        messages=[
            {
                "role": ROLES.SYSTEM,
                "content": PROMPT,
            },
            # Output format guidance is provided automatically by OpenAI SDK.
            {"role": ROLES.USER, "content": preprocessed},
        ],
        response_format=AuditResponse,
    )
    message = completion.choices[0].message
    if message.parsed:
        return message.parsed.result
    else:
        return None


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


@app.post("/submit", response_model=list[VulnerabilityReport] | str)
async def submit(request: Request, response: Response):
    source = (await request.body()).decode("utf-8")
    diagnostics = await generate_audit(source)
    if diagnostics is None:
        response.status_code = 503
        return "LLM is unavailable"
    return diagnostics


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


async def generate_contract(functions: list[str], storages: list[str]) -> SmartContract | None:
    completion = await client.beta.chat.completions.parse(
        model=GPT_MODEL,
        messages=[
            {
                "role": ROLES.SYSTEM,
                "content": get_hybrid_validator_prompt(functions, storages),
            },
            # Output format guidance is provided automatically by OpenAI SDK.
            {"role": ROLES.USER, "content": "Generate new valid smart contract"},
        ],
        response_format=SmartContract,
    )
    message = completion.choices[0].message
    if message.parsed:
        return message.parsed
    else:
        return None


@app.post("/hybrid_task", response_model=ValidatorTask)
async def get_task(request: Request):
    requested_vulnerability = (await request.body()).decode("utf-8")
    if requested_vulnerability not in VULNERABILITIES_TO_GENERATE:
        requested_vulnerability = None
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None

    raw_vulnerability = get_vulnerability(requested_vulnerability.lower() if requested_vulnerability else None)
    raw_vulnerability = Vulnerability(vulnerabilityClass=raw_vulnerability.name, code=raw_vulnerability.code)

    while tries > 0:
        tries -= 1
        vulnerability_contract = create_contract(raw_vulnerability.code)
        storages, functions = prepare_vulnerability(vulnerability_contract)
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
