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
from reports.models import (
    AnalystReasoning,
    EvidenceItem,
    InvestigationReport,
    ReasoningStatement,
)
from reports.reasoning import build_analyst_reasoning
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
    "## Analyst Reasoning",
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

_PROHIBITED_REASONING_PHRASES = (
    "confirmed malicious",
    "attacker",
    "breached",
    "compromised",
    "successful intrusion",
    "credentials stolen",
    "user clicked",
    "malware executed",
    "command and control established",
    "lateral movement occurred",
    "true positive",
    "contained",
    "remediated",
)

_PROHIBITED_GAP_ABSOLUTES = (
    "did not occur",
    "never occurred",
    "no successful login occurred",
    "user did not click",
    "malware did not execute",
)


def _load_sample_alert(path: Path) -> AlertInput:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return AlertInput.model_validate(data)


def _all_reasoning_text(reasoning: AnalystReasoning) -> str:
    parts: list[str] = []
    for section in (
        reasoning.observations,
        reasoning.assessment,
        reasoning.alternative_explanations,
        reasoning.evidence_gaps,
    ):
        for statement in section:
            parts.append(statement.text)
    return " ".join(parts).lower()


def _all_referenced_ids(reasoning: AnalystReasoning) -> list[str]:
    ids: list[str] = []
    for section in (
        reasoning.observations,
        reasoning.assessment,
        reasoning.alternative_explanations,
        reasoning.evidence_gaps,
    ):
        for statement in section:
            ids.extend(statement.evidence_ids)
    return ids


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


class ReasoningModelTests(unittest.TestCase):
    def test_reasoning_statement_validation(self) -> None:
        statement = ReasoningStatement(
            statement_id="OBS-001",
            text="The normalized alert reports SSH authentication failures.",
            evidence_ids=["EVID-002"],
        )
        self.assertEqual(statement.statement_id, "OBS-001")
        self.assertEqual(statement.evidence_ids, ["EVID-002"])

    def test_analyst_reasoning_default_empty_lists(self) -> None:
        reasoning = AnalystReasoning()
        self.assertEqual(reasoning.observations, [])
        self.assertEqual(reasoning.assessment, [])
        self.assertEqual(reasoning.alternative_explanations, [])
        self.assertEqual(reasoning.evidence_gaps, [])

    def test_analyst_reasoning_no_shared_mutable_defaults(self) -> None:
        first = AnalystReasoning()
        second = AnalystReasoning()
        first.observations.append(
            ReasoningStatement(statement_id="OBS-001", text="x")
        )
        self.assertEqual(second.observations, [])

    def test_structured_json_compatible_serialization(self) -> None:
        reasoning = AnalystReasoning(
            observations=[
                ReasoningStatement(
                    statement_id="OBS-001",
                    text="Observation text.",
                    evidence_ids=["EVID-001"],
                )
            ],
            assessment=[
                ReasoningStatement(statement_id="ASM-001", text="Assessment text.")
            ],
        )
        payload = reasoning.model_dump()
        encoded = json.dumps(payload)
        restored = json.loads(encoded)
        self.assertEqual(restored["observations"][0]["statement_id"], "OBS-001")
        self.assertEqual(restored["assessment"][0]["evidence_ids"], [])
        AnalystReasoning.model_validate(restored)


class AnalystReasoningBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ssh_alert = _load_sample_alert(_SAMPLE_SSH)
        self.phishing_alert = _load_sample_alert(_SAMPLE_PROOFPOINT)
        self.process_alert = _load_sample_alert(_SAMPLE_DEFENDER)
        self.ssh_evidence = extract_evidence(self.ssh_alert)
        self.phishing_evidence = extract_evidence(self.phishing_alert)
        self.process_evidence = extract_evidence(self.process_alert)
        self.ssh_reasoning = build_analyst_reasoning(
            self.ssh_alert, self.ssh_evidence
        )
        self.phishing_reasoning = build_analyst_reasoning(
            self.phishing_alert, self.phishing_evidence
        )
        self.process_reasoning = build_analyst_reasoning(
            self.process_alert, self.process_evidence
        )

    def test_observation_ids_begin_at_obs_001(self) -> None:
        self.assertEqual(self.ssh_reasoning.observations[0].statement_id, "OBS-001")

    def test_assessment_ids_begin_at_asm_001(self) -> None:
        self.assertEqual(self.ssh_reasoning.assessment[0].statement_id, "ASM-001")

    def test_alternative_ids_begin_at_alt_001(self) -> None:
        self.assertEqual(
            self.ssh_reasoning.alternative_explanations[0].statement_id, "ALT-001"
        )

    def test_gap_ids_begin_at_gap_001(self) -> None:
        self.assertEqual(self.ssh_reasoning.evidence_gaps[0].statement_id, "GAP-001")

    def test_ids_are_sequential_within_each_section(self) -> None:
        for section, prefix in (
            (self.ssh_reasoning.observations, "OBS"),
            (self.ssh_reasoning.assessment, "ASM"),
            (self.ssh_reasoning.alternative_explanations, "ALT"),
            (self.ssh_reasoning.evidence_gaps, "GAP"),
        ):
            expected = [f"{prefix}-{index:03d}" for index in range(1, len(section) + 1)]
            self.assertEqual([item.statement_id for item in section], expected)

    def test_ids_are_deterministic_across_repeated_builds(self) -> None:
        first = build_analyst_reasoning(self.ssh_alert, self.ssh_evidence)
        second = build_analyst_reasoning(self.ssh_alert, self.ssh_evidence)
        self.assertEqual(first.model_dump(), second.model_dump())

    def test_every_evidence_reference_exists(self) -> None:
        for reasoning, evidence in (
            (self.ssh_reasoning, self.ssh_evidence),
            (self.phishing_reasoning, self.phishing_evidence),
            (self.process_reasoning, self.process_evidence),
        ):
            known = {item.evidence_id for item in evidence}
            for evid in _all_referenced_ids(reasoning):
                self.assertIn(evid, known)

    def test_no_duplicate_evidence_ids_in_a_statement(self) -> None:
        for reasoning in (
            self.ssh_reasoning,
            self.phishing_reasoning,
            self.process_reasoning,
        ):
            for section in (
                reasoning.observations,
                reasoning.assessment,
                reasoning.alternative_explanations,
                reasoning.evidence_gaps,
            ):
                for statement in section:
                    self.assertEqual(
                        statement.evidence_ids,
                        list(dict.fromkeys(statement.evidence_ids)),
                    )

    def test_observations_of_present_fields_contain_evidence_refs(self) -> None:
        for reasoning in (
            self.ssh_reasoning,
            self.phishing_reasoning,
            self.process_reasoning,
        ):
            for statement in reasoning.observations:
                self.assertGreater(
                    len(statement.evidence_ids),
                    0,
                    msg=f"{statement.statement_id} missing evidence refs",
                )

    def test_assessments_of_reported_behavior_contain_evidence_refs(self) -> None:
        # First assessment in each supported scenario describes reported behavior.
        for reasoning in (
            self.ssh_reasoning,
            self.phishing_reasoning,
            self.process_reasoning,
        ):
            self.assertGreater(len(reasoning.assessment[0].evidence_ids), 0)

    def test_alternatives_may_be_unreferenced(self) -> None:
        for statement in self.ssh_reasoning.alternative_explanations:
            self.assertEqual(statement.evidence_ids, [])

    def test_gaps_may_be_unreferenced(self) -> None:
        for statement in self.ssh_reasoning.evidence_gaps:
            self.assertEqual(statement.evidence_ids, [])

    def test_evidence_lookup_does_not_depend_on_fixed_evid_numbers(self) -> None:
        # Omit username so source_ip shifts to an earlier EVID number.
        alert = AlertInput(
            platform="wazuh",
            alert_type="ssh_failed_login",
            severity="high",
            description="Multiple SSH authentication failures.",
            observables=AlertObservables(
                source_ip="203.0.113.45",
                destination_ip="10.0.1.15",
                hostname="prod-web-01",
            ),
        )
        evidence = extract_evidence(alert)
        by_source = {item.source: item.evidence_id for item in evidence}
        reasoning = build_analyst_reasoning(alert, evidence)
        source_ip_id = by_source["alert.observables.source_ip"]
        joined_refs = _all_referenced_ids(reasoning)
        self.assertIn(source_ip_id, joined_refs)
        # Source IP is not locked to a fixed EVID-007 from the full SSH sample.
        self.assertNotEqual(source_ip_id, "EVID-007")

    def test_ssh_cautious_authentication_failure_assessment(self) -> None:
        texts = [s.text for s in self.ssh_reasoning.assessment]
        self.assertTrue(
            any("consistent with repeated SSH authentication failures" in t for t in texts)
        )
        self.assertTrue(
            any("does not establish that authentication succeeded" in t for t in texts)
        )

    def test_ssh_does_not_claim_successful_login_or_compromise(self) -> None:
        text = _all_reasoning_text(self.ssh_reasoning)
        self.assertNotIn("login succeeded", text)
        self.assertNotIn("compromised", text)
        self.assertNotIn("brute force was confirmed", text)
        self.assertNotIn("attacker", text)

    def test_phishing_does_not_claim_delivery_click_or_theft(self) -> None:
        text = _all_reasoning_text(self.phishing_reasoning)
        self.assertNotIn("user clicked", text)
        self.assertNotIn("credentials were stolen", text)
        self.assertNotIn("mailbox was compromised", text)
        self.assertNotIn("email was delivered", text)

    def test_suspicious_process_does_not_claim_execution_or_c2(self) -> None:
        text = _all_reasoning_text(self.process_reasoning)
        self.assertNotIn("malware was confirmed", text)
        self.assertNotIn("c2 was established", text)
        self.assertNotIn("command and control established", text)
        self.assertNotIn("persistence occurred", text)
        self.assertNotIn("host was compromised", text)
        # Safe assessment may mention payload execution only as something not established.
        self.assertIn("does not establish whether a payload executed", text)

    def test_each_scenario_has_bounded_alternatives(self) -> None:
        for reasoning in (
            self.ssh_reasoning,
            self.phishing_reasoning,
            self.process_reasoning,
        ):
            self.assertGreaterEqual(len(reasoning.alternative_explanations), 1)
            self.assertLessEqual(len(reasoning.alternative_explanations), 3)

    def test_each_scenario_has_explicit_evidence_gaps(self) -> None:
        for reasoning in (
            self.ssh_reasoning,
            self.phishing_reasoning,
            self.process_reasoning,
        ):
            self.assertGreater(len(reasoning.evidence_gaps), 0)

    def test_unknown_type_conservative_assessment(self) -> None:
        alert = AlertInput(
            platform="custom",
            alert_type="weird_unknown_type",
            severity="low",
            description="Something unusual happened.",
            observables=AlertObservables(source_ip="203.0.113.99"),
        )
        evidence = extract_evidence(alert)
        reasoning = build_analyst_reasoning(alert, evidence)
        assessment_text = " ".join(s.text for s in reasoning.assessment)
        self.assertIn("requires analyst validation", assessment_text)
        self.assertIn("no scenario-specific reasoning template", assessment_text.lower())

    def test_unknown_type_produces_no_alternative_explanations(self) -> None:
        alert = AlertInput(
            platform="custom",
            alert_type="weird_unknown_type",
            severity="low",
            description="Something unusual happened.",
            observables=AlertObservables(source_ip="203.0.113.99"),
        )
        reasoning = build_analyst_reasoning(alert, extract_evidence(alert))
        self.assertEqual(reasoning.alternative_explanations, [])

    def test_unknown_type_does_not_create_unsupported_conclusions(self) -> None:
        alert = AlertInput(
            platform="custom",
            alert_type="weird_unknown_type",
            severity="low",
            description="Something unusual happened.",
            observables=AlertObservables(source_ip="203.0.113.99"),
        )
        text = _all_reasoning_text(
            build_analyst_reasoning(alert, extract_evidence(alert))
        )
        for phrase in _PROHIBITED_REASONING_PHRASES:
            self.assertNotIn(phrase, text)

    def test_no_raw_event_unique_strings_in_reasoning(self) -> None:
        # SSH raw_event-only strings
        ssh_text = _all_reasoning_text(self.ssh_reasoning)
        self.assertNotIn("5710", ssh_text)
        self.assertNotIn("54422", ssh_text)
        self.assertNotIn("sshd: authentication failed", ssh_text)
        # Defender command line unique to raw_event
        process_text = _all_reasoning_text(self.process_reasoning)
        self.assertNotIn("curl -s", process_text)
        self.assertNotIn("payload.sh | bash", process_text)
        self.assertNotIn("processCommandLine", process_text)
        # Proofpoint raw_event-only strings
        phishing_text = _all_reasoning_text(self.phishing_reasoning)
        self.assertNotIn("pp-msg-8842", phishing_text)
        self.assertNotIn("impostorScore", phishing_text)
        self.assertNotIn("Password reset required within 1 hour", phishing_text)

    def test_inputs_are_not_mutated(self) -> None:
        alert = _load_sample_alert(_SAMPLE_SSH)
        evidence = extract_evidence(alert)
        before_alert = alert.model_dump()
        before_evidence = [item.model_dump() for item in evidence]
        build_analyst_reasoning(alert, evidence)
        self.assertEqual(alert.model_dump(), before_alert)
        self.assertEqual([item.model_dump() for item in evidence], before_evidence)

    def test_gap_wording_uses_absence_phrasing(self) -> None:
        for reasoning in (
            self.ssh_reasoning,
            self.phishing_reasoning,
            self.process_reasoning,
        ):
            gap_text = " ".join(s.text for s in reasoning.evidence_gaps).lower()
            # Templates use "No … is included/present" or "not included/present/available".
            self.assertTrue(
                any(
                    phrase in gap_text
                    for phrase in (
                        "not included",
                        "not present",
                        "not available",
                        "is included",
                        "is present",
                    )
                )
            )
            for phrase in _PROHIBITED_GAP_ABSOLUTES:
                self.assertNotIn(phrase, gap_text)


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

    def test_builder_populates_analyst_reasoning(self) -> None:
        self.assertIsNotNone(self.report.analyst_reasoning)
        assert self.report.analyst_reasoning is not None
        expected = build_analyst_reasoning(self.alert, self.report.evidence)
        self.assertEqual(
            self.report.analyst_reasoning.model_dump(),
            expected.model_dump(),
        )
        self.assertGreater(len(self.report.analyst_reasoning.observations), 0)
        self.assertGreater(len(self.report.analyst_reasoning.assessment), 0)

    def test_report_serializes_to_json_compatible_data(self) -> None:
        payload = self.report.model_dump()
        encoded = json.dumps(payload)
        restored = json.loads(encoded)
        self.assertIsInstance(restored, dict)
        self.assertEqual(restored["confidence"], self.output.confidence)
        self.assertEqual(restored["alert"]["platform"], self.alert.platform)
        self.assertEqual(restored["evidence"][0]["evidence_id"], "EVID-001")
        self.assertEqual(
            restored["analyst_reasoning"]["observations"][0]["statement_id"],
            "OBS-001",
        )
        InvestigationReport.model_validate(restored)

    def test_future_list_sections_default_empty(self) -> None:
        self.assertEqual(self.report.timeline, [])

    def test_future_optional_sections_default_none(self) -> None:
        self.assertIsNone(self.report.confidence_rationale)
        self.assertIsNone(self.report.disposition)

    def test_no_disposition_timeline_or_confidence_rationale(self) -> None:
        self.assertEqual(self.report.timeline, [])
        self.assertIsNone(self.report.disposition)
        self.assertIsNone(self.report.confidence_rationale)

    def test_severity_confidence_mitre_queries_unchanged(self) -> None:
        self.assertEqual(
            self.report.severity_assessment, self.output.severity_assessment
        )
        self.assertEqual(self.report.confidence, self.output.confidence)
        self.assertEqual(
            [m.model_dump() for m in self.report.mitre],
            [m.model_dump() for m in self.output.mitre],
        )
        self.assertEqual(
            self.report.recommended_queries, self.output.recommended_queries
        )

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
        reasoning_idx = markdown.index("## Analyst Reasoning")
        summary_idx = markdown.index("## Executive Summary")
        self.assertLess(overview_idx, evidence_idx)
        self.assertLess(evidence_idx, reasoning_idx)
        self.assertLess(reasoning_idx, summary_idx)

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
        self.assertNotIn("\n## Evidence\n", "\n" + markdown)
        self.assertNotIn(
            "| ID | Kind | Category | Evidence | Value | Source | Context |",
            markdown,
        )

    def test_markdown_analyst_reasoning_subsections(self) -> None:
        markdown = render_markdown(self.report)
        self.assertIn("### Observations", markdown)
        self.assertIn("### Assessment", markdown)
        self.assertIn("### Alternative Explanations", markdown)
        self.assertIn("### Evidence Gaps", markdown)
        self.assertIn("**OBS-001:**", markdown)
        self.assertIn("**ASM-001:**", markdown)

    def test_markdown_evidence_ids_in_backticks(self) -> None:
        markdown = render_markdown(self.report)
        assert self.report.analyst_reasoning is not None
        for evid in self.report.analyst_reasoning.observations[0].evidence_ids:
            self.assertIn(f"`{evid}`", markdown)

    def test_markdown_omits_empty_evidence_reference_lines(self) -> None:
        markdown = render_markdown(self.report)
        self.assertNotIn("Evidence: \n", markdown)
        self.assertNotIn("Evidence:\n", markdown)
        # Gap statements have no evidence refs — no empty Evidence line after them.
        gap_block = markdown.split("### Evidence Gaps")[1].split("## Executive Summary")[
            0
        ]
        self.assertNotIn("Evidence:", gap_block)

    def test_markdown_omits_empty_reasoning_subsections(self) -> None:
        reasoning = AnalystReasoning(
            observations=[
                ReasoningStatement(statement_id="OBS-001", text="Only observation.")
            ]
        )
        report = self.report.model_copy(update={"analyst_reasoning": reasoning})
        markdown = render_markdown(report)
        self.assertIn("### Observations", markdown)
        self.assertNotIn("### Assessment", markdown)
        self.assertNotIn("### Alternative Explanations", markdown)
        self.assertNotIn("### Evidence Gaps", markdown)

    def test_markdown_omits_entire_reasoning_when_none_or_empty(self) -> None:
        none_report = self.report.model_copy(update={"analyst_reasoning": None})
        self.assertNotIn("## Analyst Reasoning", render_markdown(none_report))
        empty_report = self.report.model_copy(
            update={"analyst_reasoning": AnalystReasoning()}
        )
        self.assertNotIn("## Analyst Reasoning", render_markdown(empty_report))

    def test_markdown_reasoning_sanitizes_newlines_and_preserves_content(self) -> None:
        reasoning = AnalystReasoning(
            observations=[
                ReasoningStatement(
                    statement_id="OBS-001",
                    text="Line one.\nLine two | pipe remains readable.",
                    evidence_ids=["EVID-001"],
                )
            ]
        )
        report = self.report.model_copy(update={"analyst_reasoning": reasoning})
        markdown = render_markdown(report)
        self.assertIn(
            "Line one. Line two | pipe remains readable.",
            markdown,
        )
        self.assertNotIn("Line one.\nLine two", markdown)

    def test_markdown_includes_mitre_and_queries(self) -> None:
        markdown = render_markdown(self.report)
        self.assertIn("T1110", markdown)
        self.assertIn("Brute Force", markdown)
        self.assertIn("### QRadar AQL", markdown)
        self.assertIn("### Microsoft Sentinel KQL", markdown)
        self.assertIn("203.0.113.45", markdown)
        # MITRE stays in its own section, not as evidence rows.
        evidence_section = markdown.split("## Evidence")[1].split(
            "## Analyst Reasoning"
        )[0]
        self.assertNotIn("T1110", evidence_section)
        self.assertNotIn("Brute Force", evidence_section)

    def test_empty_optional_sections_do_not_malform_markdown(self) -> None:
        markdown = render_markdown(self.report)
        self.assertNotIn("## Timeline", markdown)
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
                "analyst_reasoning": None,
            }
        )
        empty_md = render_markdown(empty_report)
        self.assertIn("_None provided._", empty_md)
        self.assertIn("_No MITRE ATT&CK mappings returned._", empty_md)
        self.assertIn("_No recommended investigation queries returned._", empty_md)
        self.assertNotIn("## Evidence", empty_md)
        self.assertNotIn("## Analyst Reasoning", empty_md)

    def test_investigation_engine_output_structure_unchanged(self) -> None:
        payload = self.output.model_dump()
        self.assertEqual(set(payload.keys()), _REQUIRED_OUTPUT_KEYS)
        self.assertNotIn("evidence", payload)
        self.assertNotIn("analyst_reasoning", payload)
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
