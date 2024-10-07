from typing import Optional
import bittensor as bt
from pydantic import AliasChoices, BaseModel, Field


class VulnerabilityReport(BaseModel):
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
    # TODO: It needs to be an enum.
    vulnerability_class: str = Field(
        ...,
        title="Vulnerability Class",
        description="The category of the vulnerability.",
        serialization_alias="vulnerabilityClass",
        validation_alias=AliasChoices("vulnerabilityClass", "vulnerability_class"),
    )
    test_case: str = Field(
        ...,
        title="Test Case",
        description="A code example that exploits the vulnerability.",
        serialization_alias="testCase",
        validation_alias=AliasChoices("testCase", "test_case"),
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
        serialization_alias="priorArt",
        validation_alias=AliasChoices("priorArt", "prior_art"),
    )
    fixed_lines: str = Field(
        ...,
        title="Fixed Lines",
        description="Fixed version of the original source.",
        serialization_alias="fixedLines",
        validation_alias=AliasChoices("fixedLines", "fixed_lines"),
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
