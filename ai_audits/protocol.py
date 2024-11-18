from enum import Enum
from typing import Optional, Union
import bittensor as bt
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


__all__ = ["VulnerabilityReport", "ReferenceReport", "AuditsSynapse"]


class KnownsVulnerability(str, Enum):
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


class OtherVulnerability(BaseModel):
    description: constr(strip_whitespace=True, min_length=1)

    def __str__(self):
        return f"Other({self.description})"


class VulnerabilityClass(BaseModel):
    type: Union[KnownsVulnerability, OtherVulnerability]

    @field_validator("type", mode="before")
    def validate_type(cls, v):
        if isinstance(v, str) and v not in KnownsVulnerability._value2member_map_:
            # Treat as OtherVulnerability if it's a custom string
            return OtherVulnerability(description=v)
        return v


class VulnerabilityReport(BaseModel):
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
    # TODO: It needs to be an enum?
    vulnerability_class: VulnerabilityClass = Field(
        ...,
        title="Vulnerability Class",
        description="The category of the vulnerability. E.g. Reentrancy, Bad randomness, Forced reception, Integer overflow, Race condition, Unchecked call, Gas grief, Unguarded function, Invalid Code, et cetera.",
    )
    test_case: Optional[str] = Field(
        None,
        title="Test Case",
        description="A code example that exploits the vulnerability.",
    )
    description: str = Field(
        ...,
        title="Description",
        description="Human-readable vulnerability description, in markdown",
    )
    prior_art: list[str] = Field(
        default_factory=list,
        title="Prior Art",
        description="Similar vulnerabilities encountered in wild before",
    )
    fixed_lines: Optional[str] = Field(
        None,
        title="Fixed Lines",
        description="Fixed version of the original source.",
    )

    @field_validator("vulnerability_class", mode="before")
    def validate_vulnerability_class(cls, v):
        if isinstance(v, str):
            if v not in KnownsVulnerability._value2member_map_:
                return VulnerabilityClass(type=OtherVulnerability(description=v))
            return VulnerabilityClass(type=KnownsVulnerability(v))
        return v


class ReferenceReport(VulnerabilityReport):
    vulnerability_class: list[str] = Field(
        default_factory=list,
        title="Vulnerability Class",
        description="The category of the vulnerability. E.g. Reentrancy, Bad randomness, Forced reception, Integer overflow, Race condition, Unchecked call, Gas grief, Unguarded function, et cetera.",
    )


class AuditsSynapse(bt.Synapse):

    contract_code: str

    response: Optional[list[VulnerabilityReport]] = None

    def deserialize(self) -> Optional[list[VulnerabilityReport]]:
        """
        Deserialize the miner response.

        Returns:
        - List[dict]: The deserialized response, which is a list of dictionaries containing the extracted data.
        """
        return self.response
