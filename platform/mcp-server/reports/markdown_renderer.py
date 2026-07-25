"""Render an InvestigationReport as deterministic Markdown.

Consumes only the structured report. Does not import or call investigation
engine functions, evidence extractors, or reasoning builders. Empty Version
1.1 expansion sections (aside from populated evidence and analyst reasoning)
are omitted so the human-readable report stays intact.
"""

from __future__ import annotations

from typing import Any, Optional

from reports.models import (
    AnalystReasoning,
    EvidenceItem,
    InvestigationReport,
    ReasoningStatement,
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


def _render_reasoning_statement(statement: ReasoningStatement) -> str:
    """Render one reasoning statement with optional evidence ID list."""
    text = _sanitize_inline(statement.text)
    lines = [f"- **{statement.statement_id}:** {text}"]
    if statement.evidence_ids:
        joined = ", ".join(f"`{evid}`" for evid in statement.evidence_ids)
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
            sections.append(_render_reasoning_statement(statement))
            sections.append("")
    return "\n".join(sections).rstrip() + "\n"


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
    if report.confidence_rationale:
        parts.extend(
            [
                "## Confidence Rationale",
                "",
                report.confidence_rationale,
                "",
            ]
        )
    if report.disposition is not None:
        disposition_lines = [
            f"- **Recommendation:** {report.disposition.recommendation}",
        ]
        if report.disposition.rationale:
            disposition_lines.append(
                f"- **Rationale:** {report.disposition.rationale}"
            )
        parts.extend(
            [
                "## Disposition",
                "",
                "\n".join(disposition_lines),
                "",
            ]
        )

    return "\n".join(parts)
