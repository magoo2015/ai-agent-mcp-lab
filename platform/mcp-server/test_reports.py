"""Focused unit tests for the Version 1.1 investigation report layer.

Run from platform/mcp-server:

  python -m unittest test_reports.py
"""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from reports.builder import build_investigation_report
from reports.evidence import extract_evidence
from reports.markdown_renderer import render_markdown
from reports.models import EvidenceItem, InvestigationReport
from schemas.alert_schema import AlertInput, AlertObservables, InvestigationOutput
from tools.investigate_alert import investigate_alert

_ROOT = Path(__file__).resolve().parent
_SAMPLE_SSH = _ROOT / "sample_data" / "ssh_failed_login.json"
_SAMPLE_PROOFPOINT = _ROOT / "sample_data" / "proofpoint_phishing.json"
_SAMPLE_DEFENDER = _ROOT / "sample_data" / "defender_suspicious_process.json"

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

_MAJOR_HEADINGS = (
    "# SOC Investigation Report",
    "## Alert Overview",
    "## Evidence",
    "## Executive Summary",
    "## Severity Assessment",
    "## MITRE ATT&CK Mapping",
    "## Recommended Investigation Queries",
    "## Next Investigation Steps",
    "## Detection Engineering Opportunities",
    "## Analysis Limitations",
)

_SSH_LABEL_ORDER = (
    "Platform",
    "Alert type",
    "Vendor severity",
    "Description",
    "Username",
    "Hostname",
    "Source IP",
    "Destination IP",
)


def _load_sample_alert(path: Path) -> AlertInput:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return AlertInput.model_validate(data)


class EvidenceExtractionTests(unittest.TestCase):
    def test_ssh_sample_generates_evidence(self) -> None:
        alert = _load_sample_alert(_SAMPLE_SSH)
        items = extract_evidence(alert)
        labels = [item.label for item in items]
        self.assertEqual(labels, list(_SSH_LABEL_ORDER))
        self.assertEqual(items[0].value, "wazuh")
        self.assertEqual(items[4].value, "root")
        self.assertEqual(items[6].value, "203.0.113.45")
        self.assertEqual(items[7].value, "10.0.1.15")

    def test_proofpoint_sample_generates_email_and_url_evidence(self) -> None:
        alert = _load_sample_alert(_SAMPLE_PROOFPOINT)
        items = extract_evidence(alert)
        by_label = {item.label: item for item in items}
        self.assertIn("URL", by_label)
        self.assertIn("Sender", by_label)
        self.assertIn("Recipient", by_label)
        self.assertEqual(
            by_label["URL"].value,
            "https://corp-secure-login.example/reset?token=abc123",
        )
        self.assertEqual(
            by_label["Sender"].value, "it-support@corp-secure-login.example"
        )
        self.assertEqual(by_label["Recipient"].value, "analyst@company.com")
        self.assertEqual(by_label["URL"].category, "Indicator")
        self.assertEqual(by_label["Sender"].category, "Email")

    def test_defender_sample_generates_expected_observables(self) -> None:
        alert = _load_sample_alert(_SAMPLE_DEFENDER)
        items = extract_evidence(alert)
        by_label = {item.label: item for item in items}
        for label in (
            "Username",
            "Hostname",
            "Source IP",
            "URL",
            "File hash",
            "Process name",
        ):
            self.assertIn(label, by_label)
        self.assertEqual(by_label["Process name"].value, "bash")
        self.assertEqual(by_label["Process name"].category, "Process")
        self.assertEqual(by_label["Hostname"].value, "WORKSTATION-42")
        self.assertEqual(by_label["Username"].value, "jsmith")
        self.assertEqual(by_label["Source IP"].value, "10.0.2.88")
        self.assertEqual(by_label["URL"].value, "http://evil.example/payload.sh")
        self.assertEqual(
            by_label["File hash"].value,
            "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90",
        )

    def test_evidence_ids_start_at_evid_001(self) -> None:
        items = extract_evidence(_load_sample_alert(_SAMPLE_SSH))
        self.assertEqual(items[0].evidence_id, "EVID-001")

    def test_evidence_ids_are_sequential(self) -> None:
        items = extract_evidence(_load_sample_alert(_SAMPLE_SSH))
        expected = [f"EVID-{index:03d}" for index in range(1, len(items) + 1)]
        self.assertEqual([item.evidence_id for item in items], expected)

    def test_evidence_ids_are_deterministic(self) -> None:
        alert = _load_sample_alert(_SAMPLE_SSH)
        first = extract_evidence(alert)
        second = extract_evidence(alert)
        self.assertEqual(
            [item.model_dump() for item in first],
            [item.model_dump() for item in second],
        )

    def test_fixed_ordering_is_preserved(self) -> None:
        items = extract_evidence(_load_sample_alert(_SAMPLE_SSH))
        self.assertEqual([item.label for item in items], list(_SSH_LABEL_ORDER))

    def test_missing_observables_are_skipped(self) -> None:
        alert = AlertInput(
            platform="wazuh",
            alert_type="ssh_failed_login",
            severity="high",
            description="Test alert",
            observables=AlertObservables(source_ip="203.0.113.45"),
        )
        labels = [item.label for item in extract_evidence(alert)]
        self.assertIn("Source IP", labels)
        self.assertNotIn("Username", labels)
        self.assertNotIn("Hostname", labels)
        self.assertNotIn("Destination IP", labels)
        self.assertNotIn("URL", labels)

    def test_blank_strings_are_skipped(self) -> None:
        alert = AlertInput(
            platform="wazuh",
            alert_type="ssh_failed_login",
            severity="high",
            description="Test alert",
            observables=AlertObservables(username="", source_ip="203.0.113.45"),
        )
        labels = [item.label for item in extract_evidence(alert)]
        self.assertNotIn("Username", labels)
        self.assertIn("Source IP", labels)

    def test_whitespace_only_strings_are_skipped(self) -> None:
        alert = AlertInput(
            platform="wazuh",
            alert_type="ssh_failed_login",
            severity="high",
            description="Test alert",
            observables=AlertObservables(
                username="   ",
                hostname="\t\n",
                source_ip="203.0.113.45",
            ),
        )
        labels = [item.label for item in extract_evidence(alert)]
        self.assertNotIn("Username", labels)
        self.assertNotIn("Hostname", labels)
        self.assertIn("Source IP", labels)

    def test_extractor_does_not_mutate_alert(self) -> None:
        alert = _load_sample_alert(_SAMPLE_SSH)
        before = alert.model_dump()
        extract_evidence(alert)
        self.assertEqual(alert.model_dump(), before)

    def test_mitre_mappings_are_not_added_to_evidence(self) -> None:
        alert = _load_sample_alert(_SAMPLE_SSH)
        output = investigate_alert(alert)
        items = extract_evidence(alert)
        technique_ids = {mapping.technique_id for mapping in output.mitre}
        for item in items:
            self.assertNotEqual(item.category, "MITRE")
            self.assertNotIn(item.value, technique_ids)
            self.assertNotIn("T1110", item.value)
            self.assertNotIn("technique", item.label.lower())

    def test_raw_event_values_are_not_extracted(self) -> None:
        alert = _load_sample_alert(_SAMPLE_SSH)
        items = extract_evidence(alert)
        joined = " ".join(item.value for item in items)
        self.assertNotIn("5710", joined)
        self.assertNotIn("54422", joined)
        self.assertNotIn("sshd: authentication failed", joined)
        for item in items:
            self.assertFalse(item.source.startswith("alert.raw_event"))


class EvidenceModelTests(unittest.TestCase):
    def test_evidence_serializes_to_json_compatible_data(self) -> None:
        item = EvidenceItem(
            evidence_id="EVID-001",
            kind="metadata",
            category="Alert Metadata",
            label="Platform",
            value="wazuh",
            source="alert.platform",
            context="Platform that generated the normalized alert.",
        )
        payload = item.model_dump()
        encoded = json.dumps(payload)
        restored = json.loads(encoded)
        self.assertEqual(restored["evidence_id"], "EVID-001")
        EvidenceItem.model_validate(restored)

    def test_context_may_be_none(self) -> None:
        item = EvidenceItem(
            evidence_id="EVID-001",
            kind="observable",
            category="Network",
            label="Source IP",
            value="203.0.113.45",
            source="alert.observables.source_ip",
            context=None,
        )
        self.assertIsNone(item.context)

    def test_required_fields_are_enforced(self) -> None:
        with self.assertRaises(ValidationError):
            EvidenceItem(  # type: ignore[call-arg]
                evidence_id="EVID-001",
                kind="metadata",
                category="Alert Metadata",
                label="Platform",
                value="wazuh",
            )


class InvestigationReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = _load_sample_alert(_SAMPLE_SSH)
        self.output = investigate_alert(self.alert)
        self.report = build_investigation_report(self.alert, self.output)

    def test_build_converts_investigation_output(self) -> None:
        self.assertIsInstance(self.report, InvestigationReport)

    def test_required_fields_preserved(self) -> None:
        self.assertEqual(self.report.summary, self.output.summary)
        self.assertEqual(
            self.report.severity_assessment, self.output.severity_assessment
        )
        self.assertEqual(self.report.confidence, self.output.confidence)
        self.assertEqual(self.report.next_steps, self.output.next_steps)
        self.assertEqual(
            self.report.detection_opportunities,
            self.output.detection_opportunities,
        )
        self.assertEqual(self.report.limitations, self.output.limitations)
        self.assertEqual(
            self.report.recommended_queries, self.output.recommended_queries
        )
        self.assertEqual(len(self.report.mitre), len(self.output.mitre))
        self.assertEqual(
            self.report.mitre[0].technique_id, self.output.mitre[0].technique_id
        )
        self.assertEqual(self.report.alert.platform, self.alert.platform)
        self.assertEqual(self.report.alert.alert_type, self.alert.alert_type)
        self.assertEqual(self.report.alert.severity, self.alert.severity)
        self.assertEqual(self.report.alert.description, self.alert.description)

    def test_builder_populates_evidence(self) -> None:
        expected = extract_evidence(self.alert)
        self.assertEqual(len(self.report.evidence), len(expected))
        self.assertEqual(
            [item.model_dump() for item in self.report.evidence],
            [item.model_dump() for item in expected],
        )
        self.assertGreater(len(self.report.evidence), 0)

    def test_report_serializes_to_json_compatible_data(self) -> None:
        payload = self.report.model_dump()
        encoded = json.dumps(payload)
        restored = json.loads(encoded)
        self.assertIsInstance(restored, dict)
        self.assertEqual(restored["confidence"], self.output.confidence)
        self.assertEqual(restored["alert"]["platform"], self.alert.platform)
        self.assertEqual(restored["evidence"][0]["evidence_id"], "EVID-001")
        InvestigationReport.model_validate(restored)

    def test_future_list_sections_default_empty(self) -> None:
        self.assertEqual(self.report.timeline, [])

    def test_future_optional_sections_default_none(self) -> None:
        self.assertIsNone(self.report.analyst_reasoning)
        self.assertIsNone(self.report.confidence_rationale)
        self.assertIsNone(self.report.disposition)

    def test_builder_does_not_mutate_inputs(self) -> None:
        original_summary = self.output.summary
        original_steps = list(self.output.next_steps)
        original_ip = self.alert.observables.source_ip
        original_alert = copy.deepcopy(self.alert.model_dump())
        original_output = copy.deepcopy(self.output.model_dump())

        report = build_investigation_report(self.alert, self.output)
        report.next_steps.append("mutated-step")
        report.alert.observables.source_ip = "0.0.0.0"
        report.evidence.append(
            EvidenceItem(
                evidence_id="EVID-999",
                kind="metadata",
                category="Alert Metadata",
                label="Mutated",
                value="x",
                source="test",
            )
        )

        self.assertEqual(self.output.summary, original_summary)
        self.assertEqual(self.output.next_steps, original_steps)
        self.assertEqual(self.alert.observables.source_ip, original_ip)
        self.assertEqual(self.alert.model_dump(), original_alert)
        self.assertEqual(self.output.model_dump(), original_output)

    def test_markdown_contains_major_headings(self) -> None:
        markdown = render_markdown(self.report)
        for heading in _MAJOR_HEADINGS:
            self.assertIn(heading, markdown)
        overview_idx = markdown.index("## Alert Overview")
        evidence_idx = markdown.index("## Evidence")
        summary_idx = markdown.index("## Executive Summary")
        self.assertLess(overview_idx, evidence_idx)
        self.assertLess(evidence_idx, summary_idx)

    def test_markdown_evidence_table_header_and_row(self) -> None:
        markdown = render_markdown(self.report)
        self.assertIn(
            "| ID | Kind | Category | Evidence | Value | Source | Context |",
            markdown,
        )
        self.assertIn(
            "| EVID-001 | metadata | Alert Metadata | Platform | wazuh | "
            "alert.platform | Platform that generated the normalized alert. |",
            markdown,
        )

    def test_markdown_escapes_pipes_and_collapses_newlines(self) -> None:
        report = self.report.model_copy(
            update={
                "evidence": [
                    EvidenceItem(
                        evidence_id="EVID-001",
                        kind="metadata",
                        category="Alert Metadata",
                        label="Description",
                        value="line1\nline2 | pipe",
                        source="alert.description",
                        context="Description supplied with the normalized alert.",
                    )
                ]
            }
        )
        markdown = render_markdown(report)
        self.assertIn("line1 line2 &#124; pipe", markdown)
        self.assertNotIn("line1\nline2", markdown)
        self.assertNotIn("| pipe", markdown.split("\n")[0])

    def test_empty_evidence_omits_section(self) -> None:
        empty_evidence_report = self.report.model_copy(update={"evidence": []})
        markdown = render_markdown(empty_evidence_report)
        self.assertNotIn("## Evidence", markdown)

    def test_markdown_includes_mitre_and_queries(self) -> None:
        markdown = render_markdown(self.report)
        self.assertIn("T1110", markdown)
        self.assertIn("Brute Force", markdown)
        self.assertIn("### QRadar AQL", markdown)
        self.assertIn("### Microsoft Sentinel KQL", markdown)
        self.assertIn("203.0.113.45", markdown)
        # MITRE stays in its own section, not as evidence rows.
        evidence_section = markdown.split("## Evidence")[1].split(
            "## Executive Summary"
        )[0]
        self.assertNotIn("T1110", evidence_section)
        self.assertNotIn("Brute Force", evidence_section)

    def test_empty_optional_sections_do_not_malform_markdown(self) -> None:
        markdown = render_markdown(self.report)
        self.assertNotIn("## Timeline", markdown)
        self.assertNotIn("## Analyst Reasoning", markdown)
        self.assertNotIn("## Confidence Rationale", markdown)
        self.assertNotIn("## Disposition", markdown)
        self.assertNotIn("TBD", markdown)
        self.assertNotIn("not implemented", markdown)
        self.assertNotIn("coming soon", markdown)
        empty_report = self.report.model_copy(
            update={
                "next_steps": [],
                "detection_opportunities": [],
                "limitations": [],
                "mitre": [],
                "recommended_queries": {},
                "evidence": [],
            }
        )
        empty_md = render_markdown(empty_report)
        self.assertIn("_None provided._", empty_md)
        self.assertIn("_No MITRE ATT&CK mappings returned._", empty_md)
        self.assertIn("_No recommended investigation queries returned._", empty_md)
        self.assertNotIn("## Evidence", empty_md)

    def test_investigation_engine_output_structure_unchanged(self) -> None:
        payload = self.output.model_dump()
        self.assertEqual(set(payload.keys()), _REQUIRED_OUTPUT_KEYS)
        self.assertNotIn("evidence", payload)
        validated = InvestigationOutput.model_validate(payload)
        self.assertEqual(validated.confidence, self.output.confidence)
        self.assertIsInstance(validated.mitre, list)
        self.assertIsInstance(validated.recommended_queries, dict)
        self.assertIsInstance(validated.next_steps, list)
        self.assertIsInstance(validated.detection_opportunities, list)
        self.assertIsInstance(validated.limitations, list)
        self.assertIsInstance(validated.summary, str)
        self.assertIsInstance(validated.severity_assessment, str)


if __name__ == "__main__":
    unittest.main()
