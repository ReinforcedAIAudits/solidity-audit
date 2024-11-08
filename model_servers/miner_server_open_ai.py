import os

from fastapi import FastAPI, Request, Response
from pydantic import BaseModel
from openai import AsyncOpenAI

from ai_audits.protocol import VulnerabilityReport
from model_servers.subnet_utils import preprocess_text, ROLES


# OpenAI wants response top-level entity to be an object.
class AuditResponse(BaseModel):
    result: list[VulnerabilityReport]


client = AsyncOpenAI()
app = FastAPI()


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
"""


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
        model="gpt-4o-mini-2024-07-18",
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


@app.post("/submit", response_model=list[VulnerabilityReport] | str)
async def submit(request: Request, response: Response):
    source = (await request.body()).decode("utf-8")
    diagnostics = await generate_audit(source)
    if diagnostics is None:
        response.status_code = 503
        return "LLM is unavailable"
    return diagnostics


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5000")))
