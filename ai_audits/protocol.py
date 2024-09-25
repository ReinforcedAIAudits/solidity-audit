from typing import Optional
import bittensor as bt
from pydantic import BaseModel, Field


class VulnerabilityReport(BaseModel):
    from_line: int = Field(
        ...,
        title="From Line",
        description="The starting line number of the vulnerability in the source code.",
        alias="from",
    )
    to_line: int = Field(
        ...,
        title="To Line",
        description="The ending line number of the vulnerability in the source code.",
        alias="to",
    )
    vulnerability_class: str = Field(
        ...,
        title="Vulnerability Class",
        description="The category of the vulnerability.",
        alias="vulnerabilityClass",
    )
    description: str = Field(
        ...,
        title="Description",
        description="A detailed explanation of the vulnerability.",
    )
    test_case: str = Field(
        ...,
        title="Test Case",
        description="A code example that exploits the vulnerability.",
        alias="testCase",
    )
    prior_art: list[str] = Field(
        default_factory=list,
        title="Prior Art",
        description="Known vulnerabilities that are similar or related.",
        alias="priorArt",
    )
    fixed_lines: str = Field(
        ...,
        title="Fixed Lines",
        description="Code lines that fix the vulnerability.",
        alias="fixedLines",
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
