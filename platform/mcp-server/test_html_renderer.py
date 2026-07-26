"""Phase 6 unit tests for the standalone HTML investigation renderer.

Run from platform/mcp-server:

  python -m unittest test_html_renderer.py -v
"""

from __future__ import annotations

import copy
import json
import re
import unittest
from html import escape
from pathlib import Path

from reports.builder import build_investigation_report
from reports.html_renderer import render_html
from reports.markdown_renderer import render_markdown
from reports.models import (
    AnalystReasoning,
    ConfidenceRationale,
    ConfidenceStatement,
    DispositionLabel,
    EvidenceItem,
    InvestigationReport,
    ReasoningStatement,
    RecommendedDisposition,
    ReportMetadata,
)
from schemas.alert_schema import (
    AlertInput,
    AlertObservables,
    MitreMapping,
)
from tools.investigate_alert import investigate_alert


def _esc(value: object) -> str:
    return escape(str(value), quote=True)

_ROOT = Path(__file__).resolve().parent
_SAMPLE_SSH = _ROOT / "sample_data" / "ssh_failed_login.json"

_REQUIRED_OUTPUT_KEYS = {
    "summary",
    "severity_assessment",
    "mitre",
    "recommended_queries",
    "next_steps",
    "detection_opportunities",
    "confidence",
    "limitations",
}

_HTML_SECTION_ORDER = (
    "AI Security Investigation Report",
    "Investigation Status",
    "Alert Overview",
    "Executive Summary",
    "Recommended Disposition",
    "Evidence",
    "Analyst Reasoning",
    "Confidence Rationale",
    "Severity Assessment",
    "MITRE ATT&CK Mapping",
    "Recommended Investigation Queries",
    "Next Investigation Steps",
    "Detection Engineering Opportunities",
    "Analysis Limitations",
)

_XSS_PAYLOAD = '<script>alert(1)</script>'
_XSS_IMG = '<img src=x onerror=alert(1)>'
_XSS_LINK = '<a href="javascript:alert(1)">click</a>'
_XSS_STYLE = '<style>body{display:none}</style>'


def _load_sample_alert(path: Path) -> AlertInput:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return AlertInput.model_validate(data)


def _heading_positions(html: str) -> list[tuple[str, int]]:
    """Locate branded title and section h2 texts in document order."""
    positions: list[tuple[str, int]] = []
    h1 = "AI Security Investigation Report"
    idx = html.find(h1)
    if idx >= 0:
        positions.append((h1, idx))
    for match in re.finditer(r"<h2[^>]*>(.*?)</h2>", html, flags=re.DOTALL):
        text = re.sub(r"<[^>]+>", "", match.group(1))
        text = (
            text.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", '"')
            .replace("&#x27;", "'")
        )
        positions.append((text.strip(), match.start()))
    positions.sort(key=lambda item: item[1])
    return positions


def _confidence_section(html: str) -> str:
    start = html.find(">Confidence Rationale<")
    if start < 0:
        return ""
    end = html.find(">Severity Assessment<", start)
    if end < 0:
        end = len(html)
    return html[start:end]


def _disposition_section(html: str) -> str:
    start = html.find(">Recommended Disposition<")
    if start < 0:
        return ""
    end = html.find(">Evidence<", start)
    if end < 0:
        end = html.find(">Analyst Reasoning<", start)
    if end < 0:
        end = html.find(">Severity Assessment<", start)
    if end < 0:
        end = len(html)
    return html[start:end]


class HtmlDocumentShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = _load_sample_alert(_SAMPLE_SSH)
        self.output = investigate_alert(self.alert)
        self.report = build_investigation_report(self.alert, self.output)
        self.html = render_html(self.report)

    def test_doctype(self) -> None:
        self.assertTrue(self.html.startswith("<!doctype html>\n"))

    def test_html_lang(self) -> None:
        self.assertIn('<html lang="en">', self.html)

    def test_utf8_charset(self) -> None:
        self.assertIn('<meta charset="utf-8">', self.html)

    def test_viewport_meta(self) -> None:
        self.assertIn(
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            self.html,
        )

    def test_embedded_style(self) -> None:
        self.assertIn("<style>", self.html)
        self.assertIn("</style>", self.html)

    def test_main_header_footer(self) -> None:
        self.assertIn('<main class="report">', self.html)
        self.assertIn("<header", self.html)
        self.assertIn("<footer", self.html)

    def test_no_script_or_external_assets(self) -> None:
        lower = self.html.lower()
        self.assertNotIn("<script", lower)
        self.assertNotIn('rel="stylesheet"', lower)
        self.assertNotIn("cdn.", lower)
        self.assertNotIn("googleapis", lower)
        self.assertNotIn("fonts.google", lower)
        self.assertNotIn("@import", lower)
        self.assertNotIn("http://", lower)
        self.assertNotIn("https://", lower)


class HtmlBrandingAndOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = _load_sample_alert(_SAMPLE_SSH)
        self.output = investigate_alert(self.alert)
        self.report = build_investigation_report(self.alert, self.output)
        self.html = render_html(self.report)

    def test_branding_title(self) -> None:
        self.assertIn("<h1>AI Security Investigation Report</h1>", self.html)

    def test_footer_uses_metadata_generator(self) -> None:
        self.assertIn(
            f"Generated by {self.report.metadata.generator}",
            self.html,
        )
        self.assertIn(
            "This report supports analyst review and does not perform "
            "automated incident closure or containment.",
            self.html,
        )

    def test_section_order(self) -> None:
        found = [label for label, _ in _heading_positions(self.html)]
        expected = list(_HTML_SECTION_ORDER)
        self.assertEqual(found, expected)

    def test_executive_summary_before_disposition_and_evidence(self) -> None:
        positions = dict(_heading_positions(self.html))
        self.assertLess(
            positions["Executive Summary"],
            positions["Recommended Disposition"],
        )
        self.assertLess(
            positions["Executive Summary"],
            positions["Evidence"],
        )


class HtmlStatusAndOverviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = _load_sample_alert(_SAMPLE_SSH)
        self.output = investigate_alert(self.alert)
        self.report = build_investigation_report(self.alert, self.output)
        self.html = render_html(self.report)

    def test_status_card_fields(self) -> None:
        self.assertIn("Investigation Status", self.html)
        self.assertIn("<dt>Disposition</dt>", self.html)
        self.assertIn(
            f"<dd>{self.report.disposition.disposition.value}</dd>",
            self.html,
        )
        self.assertIn("<dt>Severity</dt>", self.html)
        self.assertIn(f"<dd>{self.report.alert.severity}</dd>", self.html)
        self.assertIn("<dt>Confidence</dt>", self.html)
        self.assertIn(f"<dd>{self.report.confidence}</dd>", self.html)
        self.assertIn("<dt>Analyst Review</dt>", self.html)
        self.assertIn("<dd>Required</dd>", self.html)
        self.assertIn("<dt>MITRE</dt>", self.html)
        self.assertIn(self.report.mitre[0].technique_id, self.html)

    def test_status_omits_disposition_and_mitre_when_absent(self) -> None:
        report = self.report.model_copy(update={"disposition": None, "mitre": []})
        html = render_html(report)
        status = html.split("Investigation Status")[1].split("Alert Overview")[0]
        self.assertNotIn("<dt>Disposition</dt>", status)
        self.assertNotIn("<dt>MITRE</dt>", status)
        self.assertIn("<dt>Analyst Review</dt>", status)
        self.assertIn("<dd>Required</dd>", status)

    def test_alert_overview_populated_fields(self) -> None:
        self.assertIn("<dt>Platform</dt>", self.html)
        self.assertIn(f"<dd>{self.report.alert.platform}</dd>", self.html)
        self.assertIn("<dt>Alert Type</dt>", self.html)
        self.assertIn(f"<dd>{self.report.alert.alert_type}</dd>", self.html)
        self.assertIn("<dt>Vendor Severity</dt>", self.html)
        self.assertIn("<dt>Confidence</dt>", self.html)
        self.assertIn("<dt>Source IP</dt>", self.html)
        self.assertIn("<dd>203.0.113.45</dd>", self.html)
        self.assertIn("<dt>Destination IP</dt>", self.html)
        self.assertIn("<dt>Hostname</dt>", self.html)
        self.assertIn("<dt>Username</dt>", self.html)

    def test_missing_observables_omitted(self) -> None:
        overview = self.html.split("Alert Overview")[1].split("Executive Summary")[0]
        self.assertNotIn("Process Name", overview)
        self.assertNotIn("File Hash", overview)
        self.assertNotIn("<dt>URL</dt>", overview)
        self.assertNotIn("Sender", overview)
        self.assertNotIn("Recipient", overview)


class HtmlContentSectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = _load_sample_alert(_SAMPLE_SSH)
        self.output = investigate_alert(self.alert)
        self.report = build_investigation_report(self.alert, self.output)
        self.html = render_html(self.report)

    def test_executive_summary_content(self) -> None:
        self.assertIn(_esc(self.report.summary), self.html)

    def test_executive_summary_placeholder_when_empty(self) -> None:
        report = self.report.model_copy(update={"summary": ""})
        html = render_html(report)
        self.assertIn(_esc("_No executive summary returned._"), html)

    def test_disposition_fields(self) -> None:
        section = _disposition_section(self.html)
        assert self.report.disposition is not None
        self.assertIn(self.report.disposition.disposition.value, section)
        self.assertIn(_esc(self.report.disposition.rationale), section)
        self.assertIn("Supporting Evidence:", section)
        self.assertIn("<code>EVID-", section)
        self.assertIn("Analyst Review Required: Yes", section)
        self.assertNotIn("Confidence", section)
        self.assertNotIn("Severity", section)
        self.assertNotIn("<button", section.lower())
        self.assertNotIn("onclick=", section.lower())
        self.assertNotIn("close the incident", section.lower())
        self.assertNotIn("disable the account", section.lower())

    def test_disposition_omits_empty_supporting_evidence(self) -> None:
        disposition = RecommendedDisposition(
            disposition=DispositionLabel.INSUFFICIENT_EVIDENCE,
            rationale="Insufficient normalized context for a stronger label.",
            evidence_ids=[],
            analyst_review_required=True,
        )
        report = self.report.model_copy(update={"disposition": disposition})
        section = _disposition_section(render_html(report))
        self.assertNotIn("Supporting Evidence:", section)
        self.assertIn("Analyst Review Required: Yes", section)

    def test_disposition_section_omitted_when_none(self) -> None:
        report = self.report.model_copy(update={"disposition": None})
        html = render_html(report)
        self.assertNotIn("Recommended Disposition", html)

    def test_evidence_table(self) -> None:
        self.assertIn('<table class="evidence-table">', self.html)
        self.assertIn('<th scope="col">ID</th>', self.html)
        self.assertIn('<th scope="col">Kind</th>', self.html)
        self.assertIn('<th scope="col">Category</th>', self.html)
        self.assertIn('<th scope="col">Evidence</th>', self.html)
        self.assertIn('<th scope="col">Value</th>', self.html)
        self.assertIn('<th scope="col">Source</th>', self.html)
        self.assertIn('<th scope="col">Context</th>', self.html)
        first = self.report.evidence[0]
        self.assertIn(
            f'<th scope="row">{first.evidence_id}</th>',
            self.html,
        )
        self.assertIn(first.kind, self.html)
        self.assertIn(first.category, self.html)
        self.assertIn(first.label, self.html)
        self.assertIn(first.value, self.html)
        self.assertIn(first.source, self.html)

    def test_evidence_order_stable(self) -> None:
        table = self.html.split('id="evidence-heading"')[1].split(
            "Analyst Reasoning"
        )[0]
        ids = [item.evidence_id for item in self.report.evidence]
        positions = [table.find(evid) for evid in ids]
        self.assertTrue(all(pos >= 0 for pos in positions))
        self.assertEqual(positions, sorted(positions))

    def test_empty_evidence_omitted(self) -> None:
        report = self.report.model_copy(update={"evidence": []})
        html = render_html(report)
        self.assertNotIn('id="evidence-heading"', html)
        self.assertNotIn('<table class="evidence-table">', html)

    def test_reasoning_groups_and_references(self) -> None:
        assert self.report.analyst_reasoning is not None
        self.assertIn("Analyst Reasoning", self.html)
        self.assertIn("<h3>Observations</h3>", self.html)
        self.assertIn("<h3>Assessment</h3>", self.html)
        self.assertIn("<h3>Alternative Explanations</h3>", self.html)
        self.assertIn("<h3>Evidence Gaps</h3>", self.html)
        obs = self.report.analyst_reasoning.observations[0]
        self.assertIn(obs.statement_id, self.html)
        self.assertIn(obs.text, self.html)
        if obs.evidence_ids:
            self.assertIn(f"<code>{obs.evidence_ids[0]}</code>", self.html)

    def test_reasoning_omits_empty_groups_and_section(self) -> None:
        partial = AnalystReasoning(
            observations=[
                ReasoningStatement(
                    statement_id="OBS-001",
                    text="Only observation present.",
                    evidence_ids=[],
                )
            ]
        )
        report = self.report.model_copy(update={"analyst_reasoning": partial})
        html = render_html(report)
        self.assertIn("<h3>Observations</h3>", html)
        self.assertNotIn("<h3>Assessment</h3>", html)
        empty = report.model_copy(update={"analyst_reasoning": None})
        empty_html = render_html(empty)
        self.assertNotIn("Analyst Reasoning", empty_html)

    def test_confidence_rationale_without_numeric_score(self) -> None:
        assert self.report.confidence_rationale is not None
        section = _confidence_section(self.html)
        self.assertIn("Supporting Factors", section)
        self.assertIn("Limiting Factors", section)
        self.assertIn("Overall", section)
        self.assertIn("SUP-001", section)
        self.assertIn("LIM-001", section)
        # Numeric investigation confidence belongs in status/overview only.
        self.assertNotRegex(section, rf">\s*{self.report.confidence}\s*<")
        self.assertNotIn(f"Confidence: {self.report.confidence}", section)

    def test_confidence_section_omitted_when_empty(self) -> None:
        report = self.report.model_copy(update={"confidence_rationale": None})
        html = render_html(report)
        self.assertNotIn("Confidence Rationale", html)

    def test_severity_assessment(self) -> None:
        self.assertIn(_esc(self.report.severity_assessment), self.html)

    def test_mitre_fields_and_empty_placeholder(self) -> None:
        mapping = self.report.mitre[0]
        self.assertIn(_esc(mapping.technique_id), self.html)
        self.assertIn(_esc(mapping.technique_name), self.html)
        self.assertIn(_esc(mapping.tactic), self.html)
        self.assertIn(_esc(mapping.confidence), self.html)
        self.assertIn(_esc(mapping.rationale), self.html)
        self.assertNotIn("attack.mitre.org", self.html)
        empty = self.report.model_copy(update={"mitre": []})
        empty_html = render_html(empty)
        self.assertIn(_esc("_No MITRE ATT&CK mappings returned._"), empty_html)

    def test_queries_pre_code_and_order(self) -> None:
        self.assertIn("<pre><code>", self.html)
        keys = list(self.report.recommended_queries.keys())
        positions = []
        for key in keys:
            title_map = {
                "qradar_aql": "QRadar AQL",
                "sentinel_kql": "Microsoft Sentinel KQL",
                "defender_advanced_hunting_kql": (
                    "Microsoft Defender Advanced Hunting KQL"
                ),
                "opensearch_dql": "OpenSearch / DQL",
            }
            title = title_map.get(key, key)
            positions.append(self.html.find(f"<h3>{title}</h3>"))
        self.assertTrue(all(pos >= 0 for pos in positions))
        self.assertEqual(positions, sorted(positions))
        query_section = self.html.split("Recommended Investigation Queries")[1].split(
            "Next Investigation Steps"
        )[0]
        self.assertNotIn("<button", query_section.lower())
        self.assertNotIn("onclick=", query_section.lower())
        sample_query = next(iter(self.report.recommended_queries.values()))[0]
        self.assertIn(_esc(sample_query), self.html)

    def test_next_steps_and_detections_and_limitations(self) -> None:
        for step in self.report.next_steps:
            self.assertIn(_esc(step), self.html)
        for item in self.report.detection_opportunities:
            self.assertIn(_esc(item), self.html)
        for item in self.report.limitations:
            self.assertIn(_esc(item), self.html)
        empty = self.report.model_copy(
            update={
                "next_steps": [],
                "detection_opportunities": [],
                "limitations": [],
            }
        )
        empty_html = render_html(empty)
        self.assertEqual(empty_html.count(_esc("_None provided._")), 3)

    def test_queries_empty_placeholder(self) -> None:
        report = self.report.model_copy(update={"recommended_queries": {}})
        html = render_html(report)
        self.assertIn(
            _esc("_No recommended investigation queries returned._"),
            html,
        )

    def test_timeline_omitted(self) -> None:
        self.assertNotIn("Timeline", self.html)
        self.assertEqual(self.report.timeline, [])


class HtmlEscapingAndDeterminismTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = _load_sample_alert(_SAMPLE_SSH)
        self.output = investigate_alert(self.alert)
        self.base = build_investigation_report(self.alert, self.output)

    def _poisoned_report(self) -> InvestigationReport:
        obs = AlertObservables(
            source_ip=_XSS_PAYLOAD,
            destination_ip=_XSS_IMG,
            hostname=_XSS_LINK,
            username=_XSS_STYLE,
            process_name=_XSS_PAYLOAD,
            file_hash=_XSS_IMG,
            url=_XSS_LINK,
            sender=_XSS_STYLE,
            recipient=_XSS_PAYLOAD,
        )
        return InvestigationReport(
            metadata=ReportMetadata(
                title=_XSS_PAYLOAD,
                generator=_XSS_IMG,
            ),
            alert=self.base.alert.model_copy(
                update={
                    "platform": _XSS_PAYLOAD,
                    "alert_type": _XSS_IMG,
                    "severity": _XSS_LINK,
                    "description": _XSS_STYLE,
                    "observables": obs,
                }
            ),
            summary=_XSS_PAYLOAD,
            severity_assessment=_XSS_IMG,
            mitre=[
                MitreMapping(
                    technique_id=_XSS_LINK,
                    technique_name=_XSS_PAYLOAD,
                    tactic=_XSS_STYLE,
                    confidence=_XSS_IMG,
                    rationale=_XSS_LINK,
                )
            ],
            recommended_queries={
                "qradar_aql": [f"SELECT {_XSS_PAYLOAD} FROM events"]
            },
            next_steps=[_XSS_PAYLOAD],
            detection_opportunities=[_XSS_IMG],
            confidence=42,
            limitations=[_XSS_STYLE],
            evidence=[
                EvidenceItem(
                    evidence_id="EVID-001",
                    kind=_XSS_PAYLOAD,
                    category=_XSS_IMG,
                    label=_XSS_LINK,
                    value=_XSS_STYLE,
                    source=_XSS_PAYLOAD,
                    context=_XSS_IMG,
                )
            ],
            analyst_reasoning=AnalystReasoning(
                observations=[
                    ReasoningStatement(
                        statement_id="OBS-001",
                        text=_XSS_PAYLOAD,
                        evidence_ids=["EVID-001"],
                    )
                ]
            ),
            confidence_rationale=ConfidenceRationale(
                supporting_factors=[
                    ConfidenceStatement(
                        statement_id="SUP-001",
                        text=_XSS_IMG,
                        evidence_ids=["EVID-001"],
                    )
                ],
                limiting_factors=[
                    ConfidenceStatement(
                        statement_id="LIM-001",
                        text=_XSS_LINK,
                        evidence_ids=[],
                    )
                ],
                summary=_XSS_STYLE,
            ),
            disposition=RecommendedDisposition(
                disposition=DispositionLabel.SUSPICIOUS_ACTIVITY,
                rationale=_XSS_PAYLOAD,
                evidence_ids=["EVID-001"],
                analyst_review_required=True,
            ),
        )

    def test_xss_payloads_are_escaped(self) -> None:
        html = render_html(self._poisoned_report())
        # Document structure may include <style>; injected report content must not.
        body_start = html.find("<body>")
        body = html[body_start:]
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertNotIn("<img src=x onerror=alert(1)>", body)
        self.assertNotIn("<img ", body)
        self.assertNotIn('href="javascript:alert(1)"', body)
        self.assertNotIn('<a href="javascript:', body)
        self.assertNotIn("<style>body{display:none}</style>", body)
        self.assertIn(_esc(_XSS_PAYLOAD), body)
        self.assertIn(_esc(_XSS_IMG), body)
        self.assertIn(_esc(_XSS_LINK), body)
        self.assertIn(_esc(_XSS_STYLE), body)

    def test_determinism(self) -> None:
        first = render_html(self.base)
        second = render_html(self.base)
        self.assertEqual(first, second)
        _ = render_markdown(self.base)
        third = render_html(self.base)
        self.assertEqual(first, third)
        self.assertNotRegex(first, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
        self.assertNotRegex(
            first,
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        )

    def test_mutation_safety(self) -> None:
        before = self.base.model_dump()
        render_html(self.base)
        after = self.base.model_dump()
        self.assertEqual(before, after)


class HtmlCssAndRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = _load_sample_alert(_SAMPLE_SSH)
        self.output = investigate_alert(self.alert)
        self.report = build_investigation_report(self.alert, self.output)
        self.html = render_html(self.report)
        style_start = self.html.find("<style>") + len("<style>")
        style_end = self.html.find("</style>")
        self.css = self.html[style_start:style_end]

    def test_print_and_wrapping_css(self) -> None:
        self.assertIn("@media print", self.css)
        self.assertIn("ui-sans-serif", self.css)
        self.assertIn("system-ui", self.css)
        self.assertIn("overflow-wrap: anywhere", self.css)
        self.assertIn("white-space: pre-wrap", self.css)
        self.assertNotIn("@import", self.css)
        self.assertNotIn("animation", self.css.lower())
        self.assertNotIn("http://", self.css)
        self.assertNotIn("https://", self.css)
        self.assertNotIn("gradient", self.css.lower())

    def test_markdown_unchanged_by_html_render(self) -> None:
        markdown_before = render_markdown(self.report)
        render_html(self.report)
        markdown_after = render_markdown(self.report)
        self.assertEqual(markdown_before, markdown_after)

    def test_investigation_output_contract_unchanged(self) -> None:
        payload = self.output.model_dump()
        self.assertEqual(set(payload.keys()), _REQUIRED_OUTPUT_KEYS)
        self.assertNotIn("evidence", payload)
        self.assertNotIn("html", payload)
        self.assertNotIn("disposition", payload)

    def test_builder_fields_unchanged_after_html(self) -> None:
        before = copy.deepcopy(self.report.model_dump())
        render_html(self.report)
        after = self.report.model_dump()
        self.assertEqual(before, after)
        rebuilt = build_investigation_report(self.alert, self.output)
        self.assertEqual(
            self.report.model_dump(),
            rebuilt.model_dump(),
        )

    def test_public_export(self) -> None:
        import reports

        self.assertTrue(hasattr(reports, "render_html"))
        self.assertEqual(reports.render_html(self.report), self.html)


if __name__ == "__main__":
    unittest.main()
