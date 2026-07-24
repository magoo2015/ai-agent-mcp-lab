"""Focused unit tests for the Version 1.1 investigation report layer.

Run from platform/mcp-server:

  python -m unittest test_reports.py
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from reports.builder import build_investigation_report
from reports.markdown_renderer import render_markdown
from reports.models import InvestigationReport
from schemas.alert_schema import AlertInput, InvestigationOutput
from tools.investigate_alert import investigate_alert

_ROOT = Path(__file__).resolve().parent
_SAMPLE = _ROOT / "sample_data" / "ssh_failed_login.json"

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
    "## Executive Summary",
    "## Severity Assessment",
    "## MITRE ATT&CK Mapping",
    "## Recommended Investigation Queries",
    "## Next Investigation Steps",
    "## Detection Engineering Opportunities",
    "## Analysis Limitations",
)


def _load_sample_alert() -> AlertInput:
    with _SAMPLE.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return AlertInput.model_validate(data)


class InvestigationReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = _load_sample_alert()
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

    def test_report_serializes_to_json_compatible_data(self) -> None:
        payload = self.report.model_dump()
        encoded = json.dumps(payload)
        restored = json.loads(encoded)
        self.assertIsInstance(restored, dict)
        self.assertEqual(restored["confidence"], self.output.confidence)
        self.assertEqual(restored["alert"]["platform"], self.alert.platform)
        # Round-trip through the report schema.
        InvestigationReport.model_validate(restored)

    def test_future_list_sections_default_empty(self) -> None:
        self.assertEqual(self.report.evidence, [])
        self.assertEqual(self.report.timeline, [])

    def test_future_optional_sections_default_none(self) -> None:
        self.assertIsNone(self.report.analyst_reasoning)
        self.assertIsNone(self.report.confidence_rationale)
        self.assertIsNone(self.report.disposition)

    def test_builder_does_not_mutate_inputs(self) -> None:
        original_summary = self.output.summary
        original_steps = list(self.output.next_steps)
        original_ip = self.alert.observables.source_ip

        report = build_investigation_report(self.alert, self.output)
        report.next_steps.append("mutated-step")
        report.alert.observables.source_ip = "0.0.0.0"

        self.assertEqual(self.output.summary, original_summary)
        self.assertEqual(self.output.next_steps, original_steps)
        self.assertEqual(self.alert.observables.source_ip, original_ip)

    def test_markdown_contains_major_headings(self) -> None:
        markdown = render_markdown(self.report)
        for heading in _MAJOR_HEADINGS:
            self.assertIn(heading, markdown)

    def test_markdown_includes_mitre_and_queries(self) -> None:
        markdown = render_markdown(self.report)
        self.assertIn("T1110", markdown)
        self.assertIn("Brute Force", markdown)
        self.assertIn("### QRadar AQL", markdown)
        self.assertIn("### Microsoft Sentinel KQL", markdown)
        self.assertIn("203.0.113.45", markdown)

    def test_empty_optional_sections_do_not_malform_markdown(self) -> None:
        markdown = render_markdown(self.report)
        self.assertNotIn("## Evidence", markdown)
        self.assertNotIn("## Timeline", markdown)
        self.assertNotIn("## Analyst Reasoning", markdown)
        self.assertNotIn("## Confidence Rationale", markdown)
        self.assertNotIn("## Disposition", markdown)
        self.assertNotIn("TBD", markdown)
        self.assertNotIn("not implemented", markdown)
        self.assertNotIn("coming soon", markdown)
        # Existing empty-list messaging remains well-formed when lists are empty.
        empty_report = self.report.model_copy(
            update={
                "next_steps": [],
                "detection_opportunities": [],
                "limitations": [],
                "mitre": [],
                "recommended_queries": {},
            }
        )
        empty_md = render_markdown(empty_report)
        self.assertIn("_None provided._", empty_md)
        self.assertIn("_No MITRE ATT&CK mappings returned._", empty_md)
        self.assertIn("_No recommended investigation queries returned._", empty_md)
        self.assertNotIn("## Evidence\n\n\n", empty_md)

    def test_investigation_engine_output_structure_unchanged(self) -> None:
        payload = self.output.model_dump()
        self.assertEqual(set(payload.keys()), _REQUIRED_OUTPUT_KEYS)
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
