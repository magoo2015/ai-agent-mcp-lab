"""Thin adapter: AlertInput + InvestigationOutput → InvestigationReport.

Copies existing investigation fields only. Does not recalculate severity,
confidence, MITRE mappings, queries, or add new conclusions.
"""

from __future__ import annotations

from schemas.alert_schema import AlertInput, InvestigationOutput

from reports.models import AlertOverview, InvestigationReport, ReportMetadata


def build_investigation_report(
    alert: AlertInput,
    output: InvestigationOutput,
) -> InvestigationReport:
    """Adapt an investigation package into a structured report.

    Inputs are not mutated. Future Version 1.1 sections remain at their
    empty defaults (empty lists / None).
    """
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
    )
