from enum import Enum, StrEnum

from pydantic import (
    BaseModel,
    Field,
    constr,
    field_validator,
)
from solidity_audit_lib import SignedMessage

__all__ = [
    "VulnerabilityReport", "ValidatorTask", "KnownVulnerability", "SmartContract", "TaskType",
    "ContractTask", "ReportMessage", "MinerResponseMessage", "TaskMessage", "OpenAIVulnerabilityReport"
]

from solidity_audit_lib.messaging import VulnerabilityReport, AuditBase, ContractTask


class KnownVulnerability(str, Enum):
    KNOWN_COMPILER_BUGS = "Known compiler bugs"
    REENTRANCY = "Reentrancy"
    GAS_GRIEFING = "Gas griefing"
    ORACLE_MANIPULATION = "Oracle manipulation"
    BAD_RANDOMNESS = "Bad randomness"
    UNEXPECTED_PRIVILEGE_GRANTS = "Unexpected privilege grants"
    FORCED_RECEPTION = "Forced reception"
    INTEGER_OVERFLOW_UNDERFLOW = "Integer overflow/underflow"
    RACE_CONDITION = "Race condition"
    UNGUARDED_FUNCTION = "Unguarded function"
    INEFFICIENT_STORAGE_KEY = "Inefficient storage key"
    FRONT_RUNNING_POTENTIAL = "Front-running potential"
    MINER_MANIPULATION = "Miner manipulation"
    STORAGE_COLLISION = "Storage collision"
    SIGNATURE_REPLAY = "Signature replay"
    UNSAFE_OPERATION = "Unsafe operation"
    INVALID_CODE = "Invalid code"


class OtherVulnerability(BaseModel):
    description: constr(strip_whitespace=True)

    def __str__(self):
        return f"Other({self.description})"


class VulnerabilityClass(BaseModel):
    type: KnownVulnerability | OtherVulnerability

    @field_validator("type", mode="before")
    def validate_type(cls, v):
        if isinstance(v, str) and v not in KnownVulnerability._value2member_map_:
            # Treat as OtherVulnerability if it's a custom string
            return OtherVulnerability(description=v)
        return v

class SmartContract(BaseModel):
    code: str = Field(..., title="Code", description="Solidity code of the contract")


class TaskType(StrEnum):
    HYBRID = "hybrid_task"
    LLM = "task"
    RANDOM_TEXT = "random_task"


class ValidatorTask(AuditBase):
    contract_code: str = Field(..., title="Contract code", description="Code of vulnerable contract")
    task_type: str | None = Field(default=None, title="Task type", description="Type of validator task")


class ReportMessage(SignedMessage):
    report: list[VulnerabilityReport]


class RelayerContainer(SignedMessage):
    content: str
    content_type: str


class TaskMessage(BaseModel):
    code: ContractTask
    validator_ss58_hotkey: str


class MinerResponseMessage(BaseModel):
    result: ReportMessage
    miner_ss58_hotkey: str
    response_time: float
