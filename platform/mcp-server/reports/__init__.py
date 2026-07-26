"""Reusable investigation report models, builder, and Markdown renderer."""

from reports.builder import build_investigation_report
from reports.confidence import build_confidence_rationale
from reports.disposition import build_recommended_disposition
from reports.evidence import extract_evidence
from reports.markdown_renderer import render_markdown
from reports.models import (
    AlertOverview,
    AnalystReasoning,
    ConfidenceRationale,
    ConfidenceStatement,
    DispositionLabel,
    EvidenceItem,
    InvestigationReport,
    ReasoningStatement,
    RecommendedDisposition,
    ReportMetadata,
    TimelineEvent,
)
from reports.reasoning import build_analyst_reasoning

__all__ = [
    "AlertOverview",
    "AnalystReasoning",
    "ConfidenceRationale",
    "ConfidenceStatement",
    "DispositionLabel",
    "EvidenceItem",
    "InvestigationReport",
    "ReasoningStatement",
    "RecommendedDisposition",
    "ReportMetadata",
    "TimelineEvent",
    "build_analyst_reasoning",
    "build_confidence_rationale",
    "build_investigation_report",
    "build_recommended_disposition",
    "extract_evidence",
    "render_markdown",
]
