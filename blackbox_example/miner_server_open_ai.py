from fastapi import FastAPI, Request, Response
from pydantic import BaseModel, Field
from openai import AsyncOpenAI
from ai_audits.protocol import VulnerabilityReport


# OpenAI wants response top-level entity to be an object.
class AuditResponse(BaseModel):
    result: list[VulnerabilityReport]


client = AsyncOpenAI()
app = FastAPI()


def preprocess_text(text: str):
    """
    For OpenAI we want LLM to provide correct line numbers, as it is bad at counting - we provide line numbers ourself.

    Good implementation of this function should also process whitespace, remove empty lines, format comments, etc.
    """
    lines = text.splitlines()
    numbered_lines = [f"Line {i + 1}: {line}" for i, line in enumerate(lines)]
    return "\n".join(numbered_lines)


async def generate_audit(source: str):
    """
    Here goes the magic.
    Reference implementation simply feeds all the data to LLM and hopes something good comes out.

    Good implementation should have good preprocessing, response augmentation for LLM to provide good prior art descriptions, it may call external linters to provide some initial guidance to LLM, etc.
    It also needs to verify the output, as LLM might hallucinate and produce invalid line ranges and other sorts of undesired output.
    """
    preprocessed = preprocess_text(source)
    completion = await client.beta.chat.completions.parse(
        model="gpt-4o-mini-2024-07-18",
        messages=[
            {
                "role": "system",
                "content": "You're a smart contract auditor. Given contract source code with explicitly specified line numbers you need to provide your audit report.",
            },
            # Output format guidance is provided automatically by OpenAI SDK.
            {"role": "user", "content": preprocessed},
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
    if diagnostics == None:
        response.status_code = 503
        return "LLM is unavailable"
    return diagnostics


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
