"""Render an InvestigationReport as deterministic Markdown.

Consumes only the structured report. Does not import or call investigation
engine functions, evidence extractors, reasoning builders, confidence
builders, or disposition builders. Empty Version 1.1 expansion sections
(aside from populated evidence, analyst reasoning, confidence rationale,
and recommended disposition) are omitted so the human-readable report stays
intact.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from reports.models import (
    AnalystReasoning,
    ConfidenceRationale,
    EvidenceItem,
    InvestigationReport,
    RecommendedDisposition,
)

_QUERY_GROUP_TITLES = {
    "qradar_aql": "QRadar AQL",
    "sentinel_kql": "Microsoft Sentinel KQL",
    "defender_advanced_hunting_kql": "Microsoft Defender Advanced Hunting KQL",
    "opensearch_dql": "OpenSearch / DQL",
}


def _bullet_list(items: list[Any]) -> str:
    if not items:
        return "_None provided._"
    lines = []
    for item in items:
        text = str(item).strip()
        lines.append(f"- {text}" if text else "-")
    return "\n".join(lines)


def _sanitize_cell(value: Optional[Any]) -> str:
    """Make a value safe for a single Markdown table cell."""
    if value is None:
        return ""
    text = str(value)
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    text = text.replace("|", "&#124;")
    return text.strip()


def _sanitize_inline(value: str) -> str:
    """Collapse embedded newlines for readable inline Markdown text."""
    text = value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return text.strip()


def _render_evidence_table(items: list[EvidenceItem]) -> str:
    header = (
        "| ID | Kind | Category | Evidence | Value | Source | Context |\n"
        "|---|---|---|---|---|---|---|"
    )
    rows = [
        "| {id} | {kind} | {category} | {label} | {value} | {source} | {context} |".format(
            id=_sanitize_cell(item.evidence_id),
            kind=_sanitize_cell(item.kind),
            category=_sanitize_cell(item.category),
            label=_sanitize_cell(item.label),
            value=_sanitize_cell(item.value),
            source=_sanitize_cell(item.source),
            context=_sanitize_cell(item.context),
        )
        for item in items
    ]
    return "\n".join([header, *rows])


def _render_linked_statement(
    statement_id: str,
    text: str,
    evidence_ids: Sequence[str],
) -> str:
    """Render one statement with optional evidence ID list (reasoning/confidence)."""
    sanitized = _sanitize_inline(text)
    lines = [f"- **{statement_id}:** {sanitized}"]
    if evidence_ids:
        joined = ", ".join(f"`{evid}`" for evid in evidence_ids)
        lines.append(f"  Evidence: {joined}")
    return "\n".join(lines)


def _reasoning_has_content(reasoning: Optional[AnalystReasoning]) -> bool:
    if reasoning is None:
        return False
    return bool(
        reasoning.observations
        or reasoning.assessment
        or reasoning.alternative_explanations
        or reasoning.evidence_gaps
    )


def _render_analyst_reasoning(reasoning: AnalystReasoning) -> str:
    """Render Analyst Reasoning subsections; omit empty ones."""
    sections: list[str] = ["## Analyst Reasoning", ""]
    subsection_map = (
        ("Observations", reasoning.observations),
        ("Assessment", reasoning.assessment),
        ("Alternative Explanations", reasoning.alternative_explanations),
        ("Evidence Gaps", reasoning.evidence_gaps),
    )
    for title, statements in subsection_map:
        if not statements:
            continue
        sections.append(f"### {title}")
        sections.append("")
        for statement in statements:
            sections.append(
                _render_linked_statement(
                    statement.statement_id,
                    statement.text,
                    statement.evidence_ids,
                )
            )
            sections.append("")
    return "\n".join(sections).rstrip() + "\n"


def _confidence_has_content(rationale: Optional[ConfidenceRationale]) -> bool:
    if rationale is None:
        return False
    return bool(
        rationale.supporting_factors
        or rationale.limiting_factors
        or (rationale.summary and rationale.summary.strip())
    )


def _render_confidence_rationale(rationale: ConfidenceRationale) -> str:
    """Render Confidence Rationale subsections; omit empty ones."""
    sections: list[str] = ["## Confidence Rationale", ""]
    if rationale.supporting_factors:
        sections.append("### Supporting Factors")
        sections.append("")
        for statement in rationale.supporting_factors:
            sections.append(
                _render_linked_statement(
                    statement.statement_id,
                    statement.text,
                    statement.evidence_ids,
                )
            )
            sections.append("")
    if rationale.limiting_factors:
        sections.append("### Limiting Factors")
        sections.append("")
        for statement in rationale.limiting_factors:
            sections.append(
                _render_linked_statement(
                    statement.statement_id,
                    statement.text,
                    statement.evidence_ids,
                )
            )
            sections.append("")
    if rationale.summary and rationale.summary.strip():
        sections.append("### Overall")
        sections.append("")
        sections.append(_sanitize_inline(rationale.summary))
        sections.append("")
    return "\n".join(sections).rstrip() + "\n"


def _render_recommended_disposition(disposition: RecommendedDisposition) -> str:
    """Render Recommended Disposition; omit Supporting Evidence when empty."""
    review = "Yes" if disposition.analyst_review_required else "No"
    lines = [
        "## Recommended Disposition",
        "",
        f"**Disposition:** {_sanitize_inline(disposition.disposition.value)}",
        "",
        _sanitize_inline(disposition.rationale),
        "",
    ]
    if disposition.evidence_ids:
        joined = ", ".join(f"`{evid}`" for evid in disposition.evidence_ids)
        lines.append(f"**Supporting Evidence:** {joined}")
        lines.append("")
    lines.append(f"**Analyst Review Required:** {review}")
    lines.append("")
    return "\n".join(lines)


def _render_mitre(report: InvestigationReport) -> str:
    mappings = report.mitre
    if not mappings:
        return "_No MITRE ATT&CK mappings returned._"

    sections: list[str] = []
    for mapping in mappings:
        sections.append(
            "\n".join(
                [
                    f"- **Technique ID:** {mapping.technique_id}",
                    f"- **Technique name:** {mapping.technique_name}",
                    f"- **Tactic:** {mapping.tactic}",
                    f"- **Confidence:** {mapping.confidence}",
                    f"- **Rationale:** {mapping.rationale}",
                ]
            )
        )
    return "\n\n".join(sections)


def _render_queries(report: InvestigationReport) -> str:
    recommended_queries = report.recommended_queries
    if not recommended_queries:
        return "_No recommended investigation queries returned._"

    sections: list[str] = []
    for key, queries in recommended_queries.items():
        title = _QUERY_GROUP_TITLES.get(key, key)
        sections.append(f"### {title}")
        if not queries:
            sections.append("_No queries in this group._")
            continue
        for query in queries:
            sections.append(f"```text\n{query}\n```")
    return "\n\n".join(sections)


def render_markdown(report: InvestigationReport) -> str:
    """Build the SOC Investigation Report Markdown from a structured report."""
    alert = report.alert
    summary = report.summary or "_No executive summary returned._"
    severity_assessment = (
        report.severity_assessment or "_No severity assessment returned._"
    )

    parts = [
        f"# {report.metadata.title}",
        "",
        "## Alert Overview",
        f"- **Platform:** {alert.platform}",
        f"- **Alert type:** {alert.alert_type}",
        f"- **Vendor severity:** {alert.severity}",
        f"- **Confidence:** {report.confidence}",
        "",
    ]

    if report.evidence:
        parts.extend(
            [
                "## Evidence",
                "",
                _render_evidence_table(report.evidence),
                "",
            ]
        )

    if _reasoning_has_content(report.analyst_reasoning):
        assert report.analyst_reasoning is not None
        parts.append(_render_analyst_reasoning(report.analyst_reasoning).rstrip())
        parts.append("")

    if _confidence_has_content(report.confidence_rationale):
        assert report.confidence_rationale is not None
        parts.append(
            _render_confidence_rationale(report.confidence_rationale).rstrip()
        )
        parts.append("")

    if report.disposition is not None:
        parts.append(_render_recommended_disposition(report.disposition).rstrip())
        parts.append("")

    parts.extend(
        [
            "## Executive Summary",
            "",
            summary,
            "",
            "## Severity Assessment",
            "",
            severity_assessment,
            "",
            "## MITRE ATT&CK Mapping",
            "",
            _render_mitre(report),
            "",
            "## Recommended Investigation Queries",
            "",
            _render_queries(report),
            "",
            "## Next Investigation Steps",
            "",
            _bullet_list(report.next_steps),
            "",
            "## Detection Engineering Opportunities",
            "",
            _bullet_list(report.detection_opportunities),
            "",
            "## Analysis Limitations",
            "",
            _bullet_list(report.limitations),
            "",
            "---",
            "",
            f"Generated by the {report.metadata.generator}.",
            "",
        ]
    )

    # Remaining Version 1.1 sections: omit when empty.
    if report.timeline:
        parts.extend(
            [
                "## Timeline",
                "",
                _bullet_list(
                    [
                        (
                            f"{event.timestamp}: {event.description}"
                            if event.timestamp
                            else event.description
                        )
                        for event in report.timeline
                    ]
                ),
                "",
            ]
        )

    return "\n".join(parts)
