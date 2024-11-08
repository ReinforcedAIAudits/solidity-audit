import json
import os

from fastapi import FastAPI, Request, HTTPException

from model_servers.subnet_utils import create_session, preprocess_text, ROLES


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


def generate_audit(source: str):
    preprocessed = preprocess_text(source)
    payload = {
        "model": os.getenv("CORCEL_MODEL", "llama-3-1-70b"),
        "temperature": 0.1,
        "max_tokens": 4 * 1024,
        "messages": [
            {"role": ROLES.SYSTEM, "content": PROMPT},
            {"role": ROLES.USER, "content": preprocessed},
        ],
        "stream": False,
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": os.getenv("CORCEL_API_KEY"),
    }

    response = create_session().post(
        "https://api.corcel.io/v1/chat/completions", json=payload, headers=headers
    )
    if response.status_code != 200:
        detail = response.text
        try:
            detail = response.json()
            if "detail" in detail:
                detail = detail["detail"]
        except:
            pass
        raise HTTPException(status_code=response.status_code, detail=detail)
    completion = response.json()
    return completion["choices"][0]["message"]["content"]


REQUIRED_KEYS = {
    "fromLine",
    "toLine",
    "vulnerabilityClass",
    "description",
}
INT_KEYS = ("fromLine", "toLine")


def try_prepare_result(result) -> list[dict] | None:
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
        if "fixedLines" in item and isinstance(item["fixedLines"], str):
            cleared["fixedLines"] = item["fixedLines"]
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
        result = try_prepare_result(result)
        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid answer from LLM")
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=int(os.getenv('SERVER_PORT', '5000')))
