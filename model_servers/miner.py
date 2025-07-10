import json
import os

from fastapi import FastAPI, HTTPException
from llama_cpp import Llama
from starlette.requests import Request
from config import Config

app = FastAPI()

llm = Llama(
    model_path="Llama-3.2-3B-Instruct-Q6_K_L.gguf",
    n_ctx=int(os.getenv("CONTEXT_SIZE", "8192")),
)

ROLE_SYSTEM = "system"
ROLE_ASSISTANT = "assistant"
ROLE_USER = "user"


PROMPT = """
You are assisting a Solidity smart contract auditor. 
Provide suggestions that might help the auditor in their analysis of the contract.
Make sure to include all observations that appear suspicious or noteworthy.
Given code with line numbers, generate an audit report in JSON format with no extra comments or explanations.

Output format:
[
    {
        "fromLine": "Start line of the vulnerability", 
        "toLine": "End line of the vulnerability",
        "vulnerabilityClass": "Type of vulnerability (e.g., Reentrancy, Integer Overflow, Invalid Code)",
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

    completion = llm.create_chat_completion(
        messages=[
            {"role": ROLE_SYSTEM, "content": PROMPT},
            {"role": ROLE_USER, "content": source},
        ],
        response_format={"type": "json_object"},
    )
    message = completion["choices"][0]["message"]["content"]
    return message


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
        if (
            len(result) == 1
            and isinstance(list(result.values())[0], list)
            and all(isinstance(item, dict) for item in list(result.values())[0])
        ):
            result = list(result.values())[0]
        else:
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
        if "testCase" in item and isinstance(item["testCase"], str):
            cleared["testCase"] = item["testCase"]
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
    tries = Config.TASK_MAX_TRIES
    is_valid, result = False, None
    contract_code = (await request.body()).decode("utf-8")
    while tries > 0:
        result = generate_audit(contract_code)
        result = try_prepare_result(result)
        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Unable to prepare audit")
    return result


def run_model_server():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5001")))


if __name__ == "__main__":
    run_model_server()
