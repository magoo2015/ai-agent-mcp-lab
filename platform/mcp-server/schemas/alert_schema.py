from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertObservables(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    file_hash: Optional[str] = None
    url: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None


class AlertInput(BaseModel):
    platform: str = Field(..., description="Source platform (e.g., wazuh, defender, proofpoint)")
    alert_type: str = Field(..., description="Normalized alert type for routing logic")
    severity: str = Field(..., description="Vendor or normalized severity label")
    description: str = Field(..., description="Human-readable alert summary")
    observables: AlertObservables = Field(default_factory=AlertObservables)
    raw_event: Optional[dict[str, Any]] = Field(
        default=None, description="Optional vendor-specific raw event payload"
    )


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str = Field(..., description="low | medium | high")
    rationale: str


class InvestigationOutput(BaseModel):
    summary: str
    severity_assessment: str
    mitre: list[MitreMapping]
    recommended_queries: dict[str, list[str]]
    next_steps: list[str]
    detection_opportunities: list[str]
    confidence: int = Field(..., ge=0, le=100)
    limitations: list[str]
