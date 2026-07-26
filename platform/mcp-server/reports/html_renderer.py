"""Render an InvestigationReport as deterministic standalone HTML.

Consumes only the structured report. Does not import or call investigation
engine functions, evidence extractors, reasoning builders, confidence
builders, or disposition builders. Pure presentation layer: embedded CSS
only, no JavaScript, no external resources, no filesystem I/O.
"""

from __future__ import annotations

from html import escape
from typing import Optional, Sequence

from reports.models import (
    AnalystReasoning,
    ConfidenceRationale,
    EvidenceItem,
    InvestigationReport,
    RecommendedDisposition,
)

_REPORT_TITLE = "AI Security Investigation Report"
_SUBTITLE = "Evidence-grounded security investigation summary"
_FOOTER_DISCLAIMER = (
    "This report supports analyst review and does not perform automated "
    "incident closure or containment."
)

_QUERY_GROUP_TITLES = {
    "qradar_aql": "QRadar AQL",
    "sentinel_kql": "Microsoft Sentinel KQL",
    "defender_advanced_hunting_kql": "Microsoft Defender Advanced Hunting KQL",
    "opensearch_dql": "OpenSearch / DQL",
}

_EMBEDDED_CSS = """
:root {
  --text: #1a2332;
  --muted: #5a6577;
  --border: #d0d7e2;
  --surface: #ffffff;
  --surface-subtle: #f4f6f9;
  --accent: #3d5a73;
  --background: #e8ecf1;
}
*, *::before, *::after { box-sizing: border-box; }
html { font-size: 16px; }
body {
  margin: 0;
  padding: 1.25rem;
  background: var(--background);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
  line-height: 1.55;
}
.report {
  max-width: 52rem;
  margin: 0 auto;
  padding: 1.75rem 1.5rem 2rem;
  background: var(--surface);
  border: 1px solid var(--border);
  box-shadow: 0 1px 3px rgba(26, 35, 50, 0.08);
}
.report-header {
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border);
}
.report-header h1 {
  margin: 0 0 0.35rem;
  font-size: 1.55rem;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: var(--text);
}
.report-header .alert-title {
  margin: 0 0 0.25rem;
  font-size: 1.05rem;
  font-weight: 600;
  color: var(--text);
  overflow-wrap: anywhere;
  word-break: break-word;
}
.report-header .platform-line {
  margin: 0 0 0.35rem;
  font-size: 0.95rem;
  color: var(--muted);
}
.report-header .subtitle {
  margin: 0;
  font-size: 0.9rem;
  color: var(--muted);
}
.section {
  margin: 1.35rem 0;
}
.section h2 {
  margin: 0 0 0.65rem;
  font-size: 1.15rem;
  font-weight: 650;
  color: var(--text);
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.3rem;
}
.section h3 {
  margin: 0.85rem 0 0.45rem;
  font-size: 1rem;
  font-weight: 600;
  color: var(--text);
}
.muted {
  color: var(--muted);
  font-style: italic;
}
.mono,
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.88em;
}
.prose {
  margin: 0;
  overflow-wrap: anywhere;
  word-break: break-word;
  white-space: pre-line;
}
.status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(7.5rem, 1fr));
  gap: 0.65rem;
  margin: 0;
  padding: 0.85rem;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
}
.status-item {
  margin: 0;
}
.status-item dt {
  margin: 0;
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
}
.status-item dd {
  margin: 0.15rem 0 0;
  font-size: 0.95rem;
  font-weight: 600;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.summary-grid {
  display: grid;
  grid-template-columns: minmax(7rem, 11rem) 1fr;
  gap: 0.35rem 1rem;
  margin: 0;
}
.summary-grid dt {
  margin: 0;
  font-weight: 600;
  color: var(--muted);
  font-size: 0.9rem;
}
.summary-grid dd {
  margin: 0;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.disposition-card {
  margin: 0;
  padding: 1rem 1.1rem;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
}
.disposition-badge {
  display: inline-block;
  margin: 0 0 0.65rem;
  padding: 0.2rem 0.55rem;
  font-size: 0.92rem;
  font-weight: 650;
  color: var(--text);
  background: var(--surface);
  border: 1px solid var(--border);
}
.disposition-card .review-line {
  margin: 0.75rem 0 0;
  font-weight: 650;
}
.table-wrap {
  overflow-x: auto;
  margin: 0;
}
.evidence-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.88rem;
}
.evidence-table th,
.evidence-table td {
  border: 1px solid var(--border);
  padding: 0.4rem 0.5rem;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.evidence-table thead th {
  background: var(--surface-subtle);
  font-weight: 650;
}
.evidence-table th[scope="row"] {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-weight: 600;
  white-space: nowrap;
}
.statement-group {
  margin: 0.75rem 0;
  padding: 0.65rem 0.75rem;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
}
.statement-group.assessment {
  border-left: 3px solid var(--accent);
}
.statement-group.alternatives {
  border-left: 3px solid #8a94a6;
}
.statement-group.gaps {
  border-left: 3px solid #9aa3b2;
}
.statement-group.supporting {
  border-left: 3px solid var(--accent);
}
.statement-group.limiting {
  border-left: 3px solid #8a94a6;
}
.statement {
  margin: 0.55rem 0;
  padding: 0.35rem 0;
}
.statement + .statement {
  border-top: 1px solid var(--border);
}
.statement-id {
  display: block;
  margin: 0 0 0.2rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.85rem;
  font-weight: 650;
}
.reference-list {
  margin: 0.3rem 0 0;
  font-size: 0.9rem;
  color: var(--muted);
}
.content-card {
  margin: 0;
  padding: 0.85rem 1rem;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
}
.mitre-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}
.mitre-table th,
.mitre-table td {
  border: 1px solid var(--border);
  padding: 0.4rem 0.5rem;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.mitre-table thead th {
  background: var(--surface-subtle);
  font-weight: 650;
}
.query-block {
  margin: 0.5rem 0 0.85rem;
  padding: 0.65rem 0.75rem;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  overflow-x: auto;
}
.query-block pre {
  margin: 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.82rem;
  line-height: 1.45;
}
.item-list {
  margin: 0.25rem 0 0;
  padding-left: 1.25rem;
}
.item-list li {
  margin: 0.3rem 0;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.limitations-section {
  padding: 0.85rem 1rem;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
}
.report-footer {
  margin-top: 1.75rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
  font-size: 0.88rem;
  color: var(--muted);
}
.report-footer p {
  margin: 0.25rem 0;
}
@media (max-width: 40rem) {
  body { padding: 0.65rem; }
  .report { padding: 1.1rem 0.85rem 1.35rem; }
  .summary-grid {
    grid-template-columns: 1fr;
    gap: 0.15rem 0;
  }
  .summary-grid dt { margin-top: 0.45rem; }
  .status-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media print {
  @page { margin: 0.65in; }
  body {
    background: #fff;
    padding: 0;
  }
  .report {
    max-width: none;
    box-shadow: none;
    border: 0;
    padding: 0;
  }
  section,
  .statement,
  .disposition-card,
  .query-block,
  .statement-group,
  .content-card,
  .limitations-section {
    break-inside: avoid;
  }
  h2,
  h3 {
    break-after: avoid;
  }
  thead {
    display: table-header-group;
  }
  pre,
  code {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
}
""".strip()


def _escape_text(value: object) -> str:
    """Escape a report-derived value for safe HTML text/attribute use."""
    return escape(str(value), quote=True)


def _present(value: object) -> bool:
    """True when a value should appear in the report (non-blank)."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def _text(value: object) -> str:
    """Escape a presentable value; empty string when absent."""
    if not _present(value):
        return ""
    return _escape_text(value)


def _prose(value: str) -> str:
    """Escape multiline prose; CSS white-space: pre-line preserves breaks."""
    return f'<p class="prose">{_escape_text(value)}</p>'


def _placeholder(message: str) -> str:
    return f'<p class="muted">{_escape_text(message)}</p>'


def _render_reference_ids(evidence_ids: Sequence[str]) -> str:
    if not evidence_ids:
        return ""
    codes = ", ".join(f"<code>{_escape_text(evid)}</code>" for evid in evidence_ids)
    return f'<p class="reference-list">Evidence: {codes}</p>'


def _reasoning_has_content(reasoning: Optional[AnalystReasoning]) -> bool:
    if reasoning is None:
        return False
    return bool(
        reasoning.observations
        or reasoning.assessment
        or reasoning.alternative_explanations
        or reasoning.evidence_gaps
    )


def _confidence_has_content(rationale: Optional[ConfidenceRationale]) -> bool:
    if rationale is None:
        return False
    return bool(
        rationale.supporting_factors
        or rationale.limiting_factors
        or (rationale.summary and rationale.summary.strip())
    )


def _header_alert_label(report: InvestigationReport) -> str:
    description = report.alert.description
    if _present(description):
        return str(description).strip()
    if _present(report.alert.alert_type):
        return str(report.alert.alert_type).strip()
    return report.alert.platform


def _render_header(report: InvestigationReport) -> str:
    alert_label = _header_alert_label(report)
    platform = report.alert.platform
    return "\n".join(
        [
            '<header class="report-header">',
            f"<h1>{_escape_text(_REPORT_TITLE)}</h1>",
            f'<p class="alert-title">{_escape_text(alert_label)}</p>',
            f'<p class="platform-line">Platform: {_escape_text(platform)}</p>',
            f'<p class="subtitle">{_escape_text(_SUBTITLE)}</p>',
            "</header>",
        ]
    )


def _render_status_card(report: InvestigationReport) -> str:
    items: list[tuple[str, str]] = []
    if report.disposition is not None:
        items.append(("Disposition", report.disposition.disposition.value))
    if _present(report.alert.severity):
        items.append(("Severity", report.alert.severity))
    items.append(("Confidence", str(report.confidence)))
    if report.disposition is not None:
        review = "Required" if report.disposition.analyst_review_required else "No"
    else:
        # Disposition omitted; keep analyst-review cue prominent.
        review = "Required"
    items.append(("Analyst Review", review))
    if report.mitre:
        technique_ids = [
            mapping.technique_id
            for mapping in report.mitre
            if _present(mapping.technique_id)
        ]
        if technique_ids:
            items.append(("MITRE", ", ".join(technique_ids)))

    rows = []
    for label, value in items:
        rows.append(
            '<div class="status-item">'
            f"<dt>{_escape_text(label)}</dt>"
            f"<dd>{_escape_text(value)}</dd>"
            "</div>"
        )
    return "\n".join(
        [
            '<section class="section" aria-labelledby="status-heading">',
            '<h2 id="status-heading">Investigation Status</h2>',
            '<dl class="status-grid">',
            *rows,
            "</dl>",
            "</section>",
        ]
    )


def _render_definition_grid(pairs: list[tuple[str, object]]) -> str:
    rows: list[str] = []
    for label, value in pairs:
        if not _present(value):
            continue
        rows.append(f"<dt>{_escape_text(label)}</dt>")
        rows.append(f"<dd>{_escape_text(value)}</dd>")
    if not rows:
        return _placeholder("No alert overview fields available.")
    return '<dl class="summary-grid">\n' + "\n".join(rows) + "\n</dl>"


def _render_alert_overview(report: InvestigationReport) -> str:
    obs = report.alert.observables
    pairs: list[tuple[str, object]] = [
        ("Platform", report.alert.platform),
        ("Alert Type", report.alert.alert_type),
        ("Vendor Severity", report.alert.severity),
        ("Confidence", report.confidence),
        ("Source IP", obs.source_ip),
        ("Destination IP", obs.destination_ip),
        ("Hostname", obs.hostname),
        ("Username", obs.username),
        ("Process Name", obs.process_name),
        ("File Hash", obs.file_hash),
        ("URL", obs.url),
        ("Sender", obs.sender),
        ("Recipient", obs.recipient),
    ]
    return "\n".join(
        [
            '<section class="section" aria-labelledby="overview-heading">',
            '<h2 id="overview-heading">Alert Overview</h2>',
            _render_definition_grid(pairs),
            "</section>",
        ]
    )


def _render_executive_summary(report: InvestigationReport) -> str:
    if _present(report.summary):
        body = _prose(report.summary)
    else:
        body = _placeholder("_No executive summary returned._")
    return "\n".join(
        [
            '<section class="section" aria-labelledby="summary-heading">',
            '<h2 id="summary-heading">Executive Summary</h2>',
            body,
            "</section>",
        ]
    )


def _render_disposition(disposition: RecommendedDisposition) -> str:
    review = "Yes" if disposition.analyst_review_required else "No"
    parts = [
        '<section class="section" aria-labelledby="disposition-heading">',
        '<h2 id="disposition-heading">Recommended Disposition</h2>',
        '<div class="disposition-card">',
        f'<div class="disposition-badge">'
        f"{_escape_text(disposition.disposition.value)}</div>",
        _prose(disposition.rationale),
    ]
    if disposition.evidence_ids:
        codes = ", ".join(
            f"<code>{_escape_text(evid)}</code>" for evid in disposition.evidence_ids
        )
        parts.append(
            f'<p class="reference-list">Supporting Evidence: {codes}</p>'
        )
    parts.append(
        f'<p class="review-line">Analyst Review Required: {_escape_text(review)}</p>'
    )
    parts.extend(["</div>", "</section>"])
    return "\n".join(parts)


def _render_evidence_table(items: list[EvidenceItem]) -> str:
    header_cells = (
        ("ID", "ID"),
        ("Kind", "Kind"),
        ("Category", "Category"),
        ("Evidence", "Evidence"),
        ("Value", "Value"),
        ("Source", "Source"),
        ("Context", "Context"),
    )
    thead = "".join(
        f'<th scope="col">{_escape_text(label)}</th>' for _, label in header_cells
    )
    body_rows: list[str] = []
    for item in items:
        context = item.context if _present(item.context) else ""
        cells = [
            f'<th scope="row">{_escape_text(item.evidence_id)}</th>',
            f"<td>{_escape_text(item.kind)}</td>",
            f"<td>{_escape_text(item.category)}</td>",
            f"<td>{_escape_text(item.label)}</td>",
            f"<td>{_escape_text(item.value)}</td>",
            f"<td>{_escape_text(item.source)}</td>",
            f"<td>{_escape_text(context) if context else ''}</td>",
        ]
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    return "\n".join(
        [
            '<section class="section" aria-labelledby="evidence-heading">',
            '<h2 id="evidence-heading">Evidence</h2>',
            '<div class="table-wrap">',
            '<table class="evidence-table">',
            f"<thead><tr>{thead}</tr></thead>",
            "<tbody>",
            *body_rows,
            "</tbody>",
            "</table>",
            "</div>",
            "</section>",
        ]
    )


def _render_statement(
    statement_id: str,
    text: str,
    evidence_ids: Sequence[str],
) -> str:
    parts = [
        '<div class="statement">',
        f'<span class="statement-id">{_escape_text(statement_id)}</span>',
        f'<p class="prose">{_escape_text(text)}</p>',
    ]
    ref = _render_reference_ids(evidence_ids)
    if ref:
        parts.append(ref)
    parts.append("</div>")
    return "\n".join(parts)


def _render_statement_group(
    title: str,
    statements: Sequence,
    css_class: str,
) -> str:
    if not statements:
        return ""
    body = "\n".join(
        _render_statement(s.statement_id, s.text, s.evidence_ids) for s in statements
    )
    return "\n".join(
        [
            f'<div class="statement-group {css_class}">',
            f"<h3>{_escape_text(title)}</h3>",
            body,
            "</div>",
        ]
    )


def _render_analyst_reasoning(reasoning: AnalystReasoning) -> str:
    groups = [
        _render_statement_group("Observations", reasoning.observations, "observations"),
        _render_statement_group("Assessment", reasoning.assessment, "assessment"),
        _render_statement_group(
            "Alternative Explanations",
            reasoning.alternative_explanations,
            "alternatives",
        ),
        _render_statement_group("Evidence Gaps", reasoning.evidence_gaps, "gaps"),
    ]
    content = "\n".join(group for group in groups if group)
    return "\n".join(
        [
            '<section class="section" aria-labelledby="reasoning-heading">',
            '<h2 id="reasoning-heading">Analyst Reasoning</h2>',
            content,
            "</section>",
        ]
    )


def _render_confidence_rationale(rationale: ConfidenceRationale) -> str:
    parts = [
        '<section class="section" aria-labelledby="confidence-heading">',
        '<h2 id="confidence-heading">Confidence Rationale</h2>',
    ]
    supporting = _render_statement_group(
        "Supporting Factors",
        rationale.supporting_factors,
        "supporting",
    )
    limiting = _render_statement_group(
        "Limiting Factors",
        rationale.limiting_factors,
        "limiting",
    )
    if supporting:
        parts.append(supporting)
    if limiting:
        parts.append(limiting)
    if rationale.summary and rationale.summary.strip():
        parts.append('<div class="statement-group overall">')
        parts.append("<h3>Overall</h3>")
        parts.append(_prose(rationale.summary))
        parts.append("</div>")
    parts.append("</section>")
    return "\n".join(parts)


def _render_severity(report: InvestigationReport) -> str:
    if _present(report.severity_assessment):
        body = (
            '<div class="content-card">'
            f"{_prose(report.severity_assessment)}"
            "</div>"
        )
    else:
        body = _placeholder("_No severity assessment returned._")
    return "\n".join(
        [
            '<section class="section" aria-labelledby="severity-heading">',
            '<h2 id="severity-heading">Severity Assessment</h2>',
            body,
            "</section>",
        ]
    )


def _render_mitre(report: InvestigationReport) -> str:
    parts = [
        '<section class="section" aria-labelledby="mitre-heading">',
        '<h2 id="mitre-heading">MITRE ATT&amp;CK Mapping</h2>',
    ]
    if not report.mitre:
        parts.append(_placeholder("_No MITRE ATT&CK mappings returned._"))
        parts.append("</section>")
        return "\n".join(parts)

    headers = (
        "Technique ID",
        "Technique name",
        "Tactic",
        "Confidence",
        "Rationale",
    )
    thead = "".join(f'<th scope="col">{_escape_text(h)}</th>' for h in headers)
    rows: list[str] = []
    for mapping in report.mitre:
        cells = [
            f"<td>{_escape_text(mapping.technique_id)}</td>",
            f"<td>{_escape_text(mapping.technique_name)}</td>",
            f"<td>{_escape_text(mapping.tactic)}</td>",
            f"<td>{_escape_text(mapping.confidence)}</td>",
            f"<td>{_escape_text(mapping.rationale)}</td>",
        ]
        rows.append("<tr>" + "".join(cells) + "</tr>")
    parts.extend(
        [
            '<div class="table-wrap">',
            '<table class="mitre-table">',
            f"<thead><tr>{thead}</tr></thead>",
            "<tbody>",
            *rows,
            "</tbody>",
            "</table>",
            "</div>",
            "</section>",
        ]
    )
    return "\n".join(parts)


def _render_query_group(key: str, queries: list[str]) -> str:
    title = _QUERY_GROUP_TITLES.get(key, key)
    parts = [f"<h3>{_escape_text(title)}</h3>"]
    if not queries:
        parts.append(_placeholder("_No queries in this group._"))
        return "\n".join(parts)
    for query in queries:
        parts.append(
            '<div class="query-block">'
            f"<pre><code>{_escape_text(query)}</code></pre>"
            "</div>"
        )
    return "\n".join(parts)


def _render_queries(report: InvestigationReport) -> str:
    parts = [
        '<section class="section" aria-labelledby="queries-heading">',
        '<h2 id="queries-heading">Recommended Investigation Queries</h2>',
    ]
    if not report.recommended_queries:
        parts.append(
            _placeholder("_No recommended investigation queries returned._")
        )
    else:
        for key, queries in report.recommended_queries.items():
            parts.append(_render_query_group(key, queries))
    parts.append("</section>")
    return "\n".join(parts)


def _render_item_list(items: list[str]) -> str:
    if not items:
        return _placeholder("_None provided._")
    lis: list[str] = []
    for item in items:
        text = str(item).strip()
        lis.append(f"<li>{_escape_text(text) if text else ''}</li>")
    return '<ul class="item-list">\n' + "\n".join(lis) + "\n</ul>"


def _render_next_steps(report: InvestigationReport) -> str:
    return "\n".join(
        [
            '<section class="section" aria-labelledby="next-steps-heading">',
            '<h2 id="next-steps-heading">Next Investigation Steps</h2>',
            _render_item_list(report.next_steps),
            "</section>",
        ]
    )


def _render_detection_opportunities(report: InvestigationReport) -> str:
    return "\n".join(
        [
            '<section class="section" aria-labelledby="detection-heading">',
            '<h2 id="detection-heading">Detection Engineering Opportunities</h2>',
            _render_item_list(report.detection_opportunities),
            "</section>",
        ]
    )


def _render_limitations(report: InvestigationReport) -> str:
    return "\n".join(
        [
            '<section class="section limitations-section" '
            'aria-labelledby="limitations-heading">',
            '<h2 id="limitations-heading">Analysis Limitations</h2>',
            _render_item_list(report.limitations),
            "</section>",
        ]
    )


def _render_footer(report: InvestigationReport) -> str:
    generator = report.metadata.generator
    if _present(generator):
        credit = f"Generated by {_escape_text(generator)}"
    else:
        credit = _escape_text("Generated by AI Security Engineering Platform")
    return "\n".join(
        [
            '<footer class="report-footer">',
            f"<p>{credit}</p>",
            f"<p>{_escape_text(_FOOTER_DISCLAIMER)}</p>",
            "</footer>",
        ]
    )


def render_html(report: InvestigationReport) -> str:
    """Render a deterministic standalone HTML investigation report."""
    alert_label = _header_alert_label(report)
    doc_title = f"{_REPORT_TITLE} — {alert_label}"

    body_parts: list[str] = [
        '<main class="report">',
        _render_header(report),
        _render_status_card(report),
        _render_alert_overview(report),
        _render_executive_summary(report),
    ]

    if report.disposition is not None:
        body_parts.append(_render_disposition(report.disposition))

    if report.evidence:
        body_parts.append(_render_evidence_table(report.evidence))

    if _reasoning_has_content(report.analyst_reasoning):
        assert report.analyst_reasoning is not None
        body_parts.append(_render_analyst_reasoning(report.analyst_reasoning))

    if _confidence_has_content(report.confidence_rationale):
        assert report.confidence_rationale is not None
        body_parts.append(
            _render_confidence_rationale(report.confidence_rationale)
        )

    body_parts.extend(
        [
            _render_severity(report),
            _render_mitre(report),
            _render_queries(report),
            _render_next_steps(report),
            _render_detection_opportunities(report),
            _render_limitations(report),
            _render_footer(report),
        ]
    )
    body_parts.append("</main>")

    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_escape_text(doc_title)}</title>",
            "<style>",
            _EMBEDDED_CSS,
            "</style>",
            "</head>",
            "<body>",
            *body_parts,
            "</body>",
            "</html>",
            "",
        ]
    )
