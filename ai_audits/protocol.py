from typing import Optional
import bittensor as bt
from pydantic import (
    AliasChoices,
    AliasGenerator,
    BaseModel,
    ConfigDict,
    Field,
)
from pydantic.alias_generators import to_camel, to_snake


__all__ = ['VulnerabilityReport', 'ReferenceReport', 'AuditsSynapse']


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
        validation_alias=AliasChoices("from", "from_line"),
    )
    to_line: int = Field(
        ...,
        title="To Line",
        description="The ending line number of the vulnerability in the source code (inclusive).",
        serialization_alias="to",
        validation_alias=AliasChoices("to", "to_line"),
    )
    # TODO: It needs to be an enum?
    vulnerability_class: str = Field(
        ...,
        title="Vulnerability Class",
        description="The category of the vulnerability. E.g. Reentrancy, Bad randomness, Forced reception, Integer overflow, Race condition, Unchecked call, Gas grief, Unguarded function, et cetera.",
    )
    test_case: str = Field(
        ...,
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
    fixed_lines: str = Field(
        ...,
        title="Fixed Lines",
        description="Fixed version of the original source.",
    )


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
