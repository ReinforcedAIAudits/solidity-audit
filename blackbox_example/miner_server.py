import logging
import time
from fastapi import Body, FastAPI

from ai_audits.protocol import VulnerabilityReport

app = FastAPI()

logger = logging.getLogger("MinerBlackbox")


@app.post("/example-endpoint")
async def add_numbers(solidity: str = Body()):
    logger.info(f"Received solidity: {solidity}")

    time.sleep(4)

    # Do some stuff...

    response = VulnerabilityReport(
    from_line=12,
    to_line=19,
    vulnerability_class="Reentrancy",
    description="The `withdrawBalance` function is vulnerable to a reentrancy attack. "
    "The function first sends Ether to the caller using `msg.sender.call.value(...)()`, and only then sets the user's balance to zero. "
    "This allows an attacker to re-enter the `withdrawBalance` function before the balance is set to zero, potentially draining the contract's funds",
    test_case="pragma solidity ^0.4.0;\n\ncontract Attacker {\n    Wallet public wallet;\n\n    function Attacker(address _walletAddress) {\n        wallet = Wallet(_walletAddress);\n    }\n\n    function attack() public payable {\n        wallet.addToBalance.value(msg.value)();\n        wallet.withdrawBalance();\n    }\n\n    function () payable {\n        if (wallet.getBalance(this) > 0) {\n            wallet.withdrawBalance();\n        }\n    }\n}",
    prior_art=["The DAO Hack", "Parity Multisig Wallet Hack"],
    fixed_lines="function withdrawBalance() {\n    uint amount = userBalance[msg.sender];\n    userBalance[msg.sender] = 0;\n    if (!msg.sender.call.value(amount)()) {\n        throw;\n    }\n}",
)

    logger.info(f"Sending response: {response}")
    return response


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, port=5000)
