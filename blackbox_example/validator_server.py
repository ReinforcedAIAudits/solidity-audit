import logging

import random
import time
from typing import List

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
    mutated_contract_code = contract.replace(
        "contract Wallet", f"contract Wallet_{int(time.time())}"
    )

    logger.info(f"Generated contract: {mutated_contract_code}")
    return mutated_contract_code


@app.post("/validate")
async def validate(vulnerability_report: List[VulnerabilityReport] = Body()):
    for report in vulnerability_report:
        if not all(value is not None for value in vars(report).values()):
            logger.info("Not all fields presented at vulnerability report")
            raise HTTPException(status_code=400, detail="Incorrect report")

        if (
            report.from_line > report.to_line
            or report.from_line != 12
            or report.to_line != 19
        ):
            logger.info("Incorrect location information")
            raise HTTPException(status_code=400, detail="Incorrect lines information")
    return


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, port=5001)
