import logging

import random
import time
from typing import List
from types import SimpleNamespace

from fastapi import Body, FastAPI, HTTPException

from ai_audits.protocol import VulnerabilityReport

app = FastAPI()

miners_verifications = {}
execution_events = {}

logger = logging.getLogger("AuditValidatorBlackbox")


@app.get("/generate_contract")
async def generate_contract():

    logger.info("Generating contract...")
    time.sleep(4)

    # Do some stuff...

    contract = """
contract Wallet {
    mapping (address => uint) userBalance;
   
    function getBalance(address u) constant returns(uint){
        return userBalance[u];
    }

    function addToBalance() payable{
        userBalance[msg.sender] += msg.value;
    }   

    function withdrawBalance(){
        // send userBalance[msg.sender] ethers to msg.sender
        // if mgs.sender is a contract, it will call its fallback function
        if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){
            throw;
        }
        userBalance[msg.sender] = 0;
    }   
}
"""
    report = [
        VulnerabilityReport(
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
    ]

    mutated_contract_code = contract.replace(
        "contract Wallet", f"contract Wallet_{int(time.time())}"
    )

    logger.info(f"Generated contract: {mutated_contract_code}")
    return SimpleNamespace(code=mutated_contract_code, report=report)


@app.post("/validate")
async def validate(vulnerability_report: List[VulnerabilityReport] = Body()):
    for report in vulnerability_report:
        if report.from_line != 12 or report.to_line != 19:
            logger.info("Incorrect location information for report: %s", report)
            return {"result": 0.0}

    return {"result": 1.0}


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, port=5001)
