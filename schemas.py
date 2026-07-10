from pydantic import BaseModel, Field
from typing import Optional


class PullConfigInput(BaseModel):
    section_keyword: Optional[str] = Field(
        default=None,
        description="Optional keyword to filter running-config, e.g. 'interface' or 'line vty'."
    )


class RetrievePolicyInput(BaseModel):
    query: str = Field(..., description="What kind of config/behavior to check policy for, e.g. 'SSH access control'")


class ProposeComplianceFixInput(BaseModel):
    finding: str = Field(..., description="What was found to be non-compliant")
    policy_citation: str = Field(..., description="The exact policy clause this finding violates")
    proposed_commands: list[str]
    severity: str = Field(..., description="low | medium | high")
