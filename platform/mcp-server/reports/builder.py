"""Thin adapter: AlertInput + InvestigationOutput → InvestigationReport.

Copies existing investigation fields and attaches deterministic evidence,
analyst reasoning, confidence rationale, and recommended disposition from
normalized alert fields. Does not recalculate severity, confidence, MITRE
mappings, or queries, and does not parse raw_event.
"""

from __future__ import annotations

from schemas.alert_schema import AlertInput, InvestigationOutput

from reports.confidence import build_confidence_rationale
from reports.disposition import build_recommended_disposition
from reports.evidence import extract_evidence
from reports.models import AlertOverview, InvestigationReport, ReportMetadata
from reports.reasoning import build_analyst_reasoning


def build_investigation_report(
    alert: AlertInput,
    output: InvestigationOutput,
) -> InvestigationReport:
    """Adapt an investigation package into a structured report.

    Inputs are not mutated. Evidence, analyst reasoning, confidence
    rationale, and recommended disposition are derived only from normalized
    AlertInput fields. Timeline remains at its empty default. Numeric
    confidence is copied from InvestigationOutput unchanged.
    """
    evidence = extract_evidence(alert)
    analyst_reasoning = build_analyst_reasoning(alert, evidence)
    confidence_rationale = build_confidence_rationale(alert, evidence)
    recommended_disposition = build_recommended_disposition(alert, evidence)
    return InvestigationReport(
        metadata=ReportMetadata(),
        alert=AlertOverview(
            platform=alert.platform,
            alert_type=alert.alert_type,
            severity=alert.severity,
            description=alert.description,
            observables=alert.observables.model_copy(deep=True),
        ),
        summary=output.summary,
        severity_assessment=output.severity_assessment,
        mitre=[mapping.model_copy(deep=True) for mapping in output.mitre],
        recommended_queries={
            key: list(queries) for key, queries in output.recommended_queries.items()
        },
        next_steps=list(output.next_steps),
        detection_opportunities=list(output.detection_opportunities),
        confidence=output.confidence,
        limitations=list(output.limitations),
        evidence=evidence,
        analyst_reasoning=analyst_reasoning,
        confidence_rationale=confidence_rationale,
        disposition=recommended_disposition,
    )
