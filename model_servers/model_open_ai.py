import os
import random

from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel
from openai import AsyncOpenAI

from ai_audits.protocol import VulnerabilityReport, ValidatorTask, KnownVulnerability
from ai_audits.subnet_utils import preprocess_text, ROLES, SolcSingleton


# OpenAI wants response top-level entity to be an object.
class AuditResponse(BaseModel):
    result: list[VulnerabilityReport]


solc = SolcSingleton()

client = AsyncOpenAI()
app = FastAPI()


GPT_MODEL = "gpt-4o-mini-2024-07-18"


PROMPT = """
You're a smart contract auditor. 
Given contract source code with explicitly specified line numbers, you need to provide your audit report. 

If the source code is invalid or cannot be meaningfully analyzed:
- Generate a single vulnerability report entry with the following details:
  - from_line: 1 (start of the code)
  - to_line: the total number of lines in the code
  - vulnerability_class: "Invalid Code"
  - description: A message stating that the entire code is considered invalid for audit processing.

Otherwise, analyze and report any specific vulnerabilities with their line ranges, descriptions, and fixes.
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


VULNERABILITIES_TO_GENERATE = [
    # KnownVulnerability.KNOWN_COMPILER_BUGS.value,  # ambiguous, skip this
    KnownVulnerability.REENTRANCY.value,  # works
    KnownVulnerability.GAS_GRIEFING.value,  # works
    # KnownVulnerability.ORACLE_MANIPULATION.value,  # doesn't works
    KnownVulnerability.BAD_RANDOMNESS.value,  # works
    # KnownVulnerability.UNEXPECTED_PRIVILEGE_GRANTS.value,  # doesn't works
    KnownVulnerability.FORCED_RECEPTION.value,  # partially works
    # KnownVulnerability.INTEGER_OVERFLOW_UNDERFLOW.value,  # doesn't works
    KnownVulnerability.RACE_CONDITION.value,  # partially works
    KnownVulnerability.UNGUARDED_FUNCTION.value,  # works
    # KnownVulnerability.INEFFICIENT_STORAGE_KEY.value,  # doesn't works
    # KnownVulnerability.FRONT_RUNNING_POTENTIAL.value,  # doesn't works
    # KnownVulnerability.MINER_MANIPULATION.value,  # doesn't works
    # KnownVulnerability.STORAGE_COLLISION.value,  # doesn't works
    KnownVulnerability.SIGNATURE_REPLAY.value,  # works
    KnownVulnerability.UNSAFE_OPERATION.value,  # works
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
    possible_vulnerabilities = random.sample(
        VULNERABILITIES_TO_GENERATE, min(3, len(VULNERABILITIES_TO_GENERATE))
    ) if requested_vulnerability is None else [requested_vulnerability]
    completion = await client.beta.chat.completions.parse(
        model=GPT_MODEL,
        messages=[
            {"role": ROLES.SYSTEM, "content": PROMPT_VALIDATOR},
            # Output format guidance is provided automatically by OpenAI SDK.
            {
                "role": ROLES.USER,
                "content": f"Generate new vulnerable contract with one of "
                           f"vulnerabilities: {', '.join(possible_vulnerabilities)}"
            },
        ],
        response_format=ValidatorTask,
        temperature=0.3
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


if __name__ == "__main__":
    import uvicorn

    solc.install_solc()

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5000")))
