"""Structured investigation report models (Version 1.1 report layer).

Preserves existing investigation content while providing typed fields for
evidence, analyst reasoning, and confidence rationale, plus expansion
points for timeline and disposition. Unpopulated sections default to
empty collections or None — they are not filled with placeholder text.
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
    """Factual evidence extracted from normalized alert fields."""

    evidence_id: str
    kind: str
    category: str
    label: str
    value: str
    source: str
    context: Optional[str] = None


class ReasoningStatement(BaseModel):
    """One deterministic analyst-reasoning statement with optional evidence links."""

    statement_id: str
    text: str
    evidence_ids: list[str] = Field(default_factory=list)


class AnalystReasoning(BaseModel):
    """Structured evidence-based analyst reasoning (Version 1.1 Phase 3)."""

    observations: list[ReasoningStatement] = Field(default_factory=list)
    assessment: list[ReasoningStatement] = Field(default_factory=list)
    alternative_explanations: list[ReasoningStatement] = Field(default_factory=list)
    evidence_gaps: list[ReasoningStatement] = Field(default_factory=list)


class ConfidenceStatement(BaseModel):
    """One deterministic confidence-rationale statement with optional evidence links."""

    statement_id: str
    text: str
    evidence_ids: list[str] = Field(default_factory=list)


class ConfidenceRationale(BaseModel):
    """Structured confidence context from normalized evidence (Version 1.1 Phase 4)."""

    supporting_factors: list[ConfidenceStatement] = Field(default_factory=list)
    limiting_factors: list[ConfidenceStatement] = Field(default_factory=list)
    summary: Optional[str] = None


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

    # Evidence is populated from normalized alert fields (Phase 2).
    evidence: list[EvidenceItem] = Field(default_factory=list)
    # Analyst reasoning is populated from evidence + alert type (Phase 3).
    analyst_reasoning: Optional[AnalystReasoning] = None
    # Confidence rationale from normalized evidence only (Phase 4).
    confidence_rationale: Optional[ConfidenceRationale] = None
    # Remaining Version 1.1 expansion points — empty until future work.
    timeline: list[TimelineEvent] = Field(default_factory=list)
    disposition: Optional[Disposition] = None
