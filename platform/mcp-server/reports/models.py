"""Structured investigation report models (Version 1.1 report layer).

Preserves existing investigation content while providing typed expansion
points for evidence, timeline, analyst reasoning, confidence rationale,
and disposition. Future sections default to empty collections or None —
they are not populated with placeholder text.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from schemas.alert_schema import AlertObservables, MitreMapping


class ReportMetadata(BaseModel):
    """Deterministic report header metadata."""

    title: str = "SOC Investigation Report"
    generator: str = "offline SOC Investigation Tools MCP server"
    schema_version: str = "1.1"


class AlertOverview(BaseModel):
    """Alert metadata copied into the report for presentation."""

    platform: str
    alert_type: str
    severity: str
    description: str
    observables: AlertObservables = Field(default_factory=AlertObservables)


class EvidenceItem(BaseModel):
    """Expansion point for Version 1.1 evidence tables (not yet populated)."""

    label: str
    value: str
    source: Optional[str] = None


class TimelineEvent(BaseModel):
    """Expansion point for Version 1.1 investigation timelines (not yet populated)."""

    timestamp: Optional[str] = None
    description: str
    source: Optional[str] = None


class Disposition(BaseModel):
    """Expansion point for Version 1.1 recommended disposition (not yet populated)."""

    recommendation: str
    rationale: Optional[str] = None


class InvestigationReport(BaseModel):
    """Structured SOC investigation report built from alert + InvestigationOutput."""

    metadata: ReportMetadata = Field(default_factory=ReportMetadata)
    alert: AlertOverview
    summary: str
    severity_assessment: str
    mitre: list[MitreMapping]
    recommended_queries: dict[str, list[str]]
    next_steps: list[str]
    detection_opportunities: list[str]
    confidence: int = Field(..., ge=0, le=100)
    limitations: list[str]

    # Version 1.1 expansion points — empty until populated by future work.
    evidence: list[EvidenceItem] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    analyst_reasoning: Optional[str] = None
    confidence_rationale: Optional[str] = None
    disposition: Optional[Disposition] = None
