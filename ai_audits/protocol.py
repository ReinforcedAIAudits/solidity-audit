from enum import Enum, StrEnum

from pydantic import (
    AliasChoices,
    AliasGenerator,
    BaseModel,
    ConfigDict,
    Field,
    constr,
    field_validator,
)
from pydantic.alias_generators import to_camel, to_snake
from solidity_audit_lib import SignedMessage

__all__ = [
    "VulnerabilityReport", "ValidatorTask", "KnownVulnerability", "SmartContract", "TaskType",
    "ContractTask", "ReportMessage", "MinerResponseMessage", "TaskMessage", "OpenAIVulnerabilityReport"
]


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


class AuditBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=AliasGenerator(
            validation_alias=lambda field_name: AliasChoices(
                to_camel(field_name),
                to_snake(field_name),
            ),
            serialization_alias=to_camel,
        )
    )
    from_line: int = Field(
        ...,
        title="From Line",
        description="The starting line number of the vulnerability in the source code. The line numbers start from one.",
        serialization_alias="from",
        validation_alias=AliasChoices("from", "from_line", "fromLine"),
    )
    to_line: int = Field(
        ...,
        title="To Line",
        description="The ending line number of the vulnerability in the source code (inclusive).",
        serialization_alias="to",
        validation_alias=AliasChoices("to", "to_line", "toLine"),
    )
    vulnerability_class: str = Field(
        ...,
        title="Vulnerability Class",
        description="The category of the vulnerability. "
        "E.g. Reentrancy, Bad randomness, Forced reception, Integer overflow, Race condition, "
        "Unchecked call, Gas griefing, Unguarded function, Invalid Code, et cetera.",
    )

    # @field_validator("vulnerability_class", mode="before")
    # def validate_vulnerability_class(cls, v):
    #     if isinstance(v, str):
    #         if v not in KnownVulnerability._value2member_map_:
    #             return VulnerabilityClass(type=OtherVulnerability(description=v))
    #         return VulnerabilityClass(type=KnownVulnerability(v))
    #     return v


class OpenAIVulnerabilityReport(AuditBase):
    test_case: str | None = Field(
        None,
        title="Test Case",
        description="A code example that exploits the vulnerability.",
    )
    description: str | None = Field(
        None,
        title="Description",
        description="Human-readable vulnerability description, in markdown",
    )
    prior_art: list[str] = Field(
        default_factory=list,
        title="Prior Art",
        description="Similar vulnerabilities encountered in wild before",
    )
    fixed_lines: str | None = Field(
        None,
        title="Fixed Lines",
        description="Fixed version of the original source.",
    )

class VulnerabilityReport(OpenAIVulnerabilityReport):
    is_suggestion: bool = Field(False, title="Is Suggestion", description="Whether the fix is a suggestion or not")


class SmartContract(BaseModel):
    code: str = Field(..., title="Code", description="Solidity code of the contract")


class TaskType(StrEnum):
    HYBRID = "hybrid_task"
    LLM = "task"
    RANDOM_TEXT = "random_task"


class ValidatorTask(AuditBase):
    contract_code: str = Field(..., title="Contract code", description="Code of vulnerable contract")
    task_type: str | None = Field(default=None, title="Task type", description="Type of validator task")


class ContractTask(SignedMessage):
    uid: int
    contract_code: str


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
