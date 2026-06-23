from datetime import datetime
from mcp.server.fastmcp import FastMCP
import json
import re
import subprocess
from pathlib import Path

mcp = FastMCP("soc-assistant")

LAB_ROOT = Path("/Users/ghost/ai-agent-mcp-lab").resolve()

@mcp.tool()
def parse_wazuh_alert(file_path: str) -> str:
    """
    Parse a Wazuh alert JSON file and extract SOC-friendly observables.
    """
    requested_path = (LAB_ROOT / file_path).resolve()

    if not str(requested_path).startswith(str(LAB_ROOT)):
        return "Error: File path is outside the allowed lab directory."

    if not requested_path.exists():
        return f"Error: File not found: {file_path}"

    with open(requested_path, "r") as f:
        alert = json.load(f)

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    decoder = alert.get("decoder", {})
    full_log = alert.get("full_log", "")

    source_port = None
    match = re.search(r"port (\d+)", full_log)
    if match:
        source_port = match.group(1)

    result = {
        "status": "ok",
        "summary": (
    f"SSH failed authentication for user {alert.get('user')} "
    f"from {alert.get('srcip')} on {agent.get('name')}"
    ),
        "observables": {
            "timestamp": alert.get("timestamp"),
            "source_ip": alert.get("srcip"),
            "source_port": source_port,
            "target_user": alert.get("user"),
            "host": agent.get("name"),
            "agent_id": agent.get("id"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "decoder": decoder.get("name"),
            "raw_log": full_log
        },
        "analyst_note": (
            "This tool extracts facts only. "
            "The AI should determine severity, confidence, and next steps."
)
    }

    return json.dumps(result, indent=2)


# Beginner-friendly regex patterns for common sshd auth log lines (lab sample format).
_FAILED_PASSWORD_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<username>\S+) from "
    r"(?P<source_ip>[\d.]+)"
)
_ACCEPTED_AUTH_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?P<auth_method>password|publickey) for (?P<username>\S+) from "
    r"(?P<source_ip>[\d.]+)"
)


def _parse_linux_auth_log_data(requested_path: Path) -> dict:
    """Parse SSH auth events from a local log file (shared by MCP tools)."""
    failed_logins: list[dict] = []
    successful_logins: list[dict] = []
    source_ip_set: set[str] = set()
    user_set: set[str] = set()
    failure_seen_by_ip: dict[str, bool] = {}
    success_after_failure_by_ip: dict[str, bool] = {}

    with open(requested_path, "r") as f:
        for line in f:
            raw_log = line.rstrip("\n")
            if not raw_log:
                continue

            if "Failed password" in raw_log:
                match = _FAILED_PASSWORD_RE.match(raw_log)
                if not match:
                    continue
                username = match.group("username")
                source_ip = match.group("source_ip")
                failed_logins.append(
                    {
                        "timestamp": match.group("timestamp"),
                        "username": username,
                        "source_ip": source_ip,
                        "raw_log": raw_log,
                    }
                )
                source_ip_set.add(source_ip)
                user_set.add(username)
                failure_seen_by_ip[source_ip] = True
            elif "Accepted password" in raw_log or "Accepted publickey" in raw_log:
                match = _ACCEPTED_AUTH_RE.match(raw_log)
                if not match:
                    continue
                username = match.group("username")
                source_ip = match.group("source_ip")
                successful_logins.append(
                    {
                        "timestamp": match.group("timestamp"),
                        "username": username,
                        "source_ip": source_ip,
                        "auth_method": match.group("auth_method"),
                        "raw_log": raw_log,
                    }
                )
                source_ip_set.add(source_ip)
                user_set.add(username)
                if failure_seen_by_ip.get(source_ip):
                    success_after_failure_by_ip[source_ip] = True

    source_ips = sorted(source_ip_set)
    users = sorted(user_set)
    event_count = len(failed_logins) + len(successful_logins)

    return {
        "event_count": event_count,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "source_ips": source_ips,
        "users": users,
        "success_after_failure_ips": sorted(success_after_failure_by_ip),
    }


@mcp.tool()
def parse_linux_auth_log(file_path: str) -> str:
    """
    Parse a local Linux SSH/auth log sample and extract failed and successful
    login events. Reads the file from the lab directory only (no SSH commands,
    no API calls).
    """
    requested_path = (LAB_ROOT / file_path).resolve()

    if not str(requested_path).startswith(str(LAB_ROOT)):
        return "Error: File path is outside the allowed lab directory."

    if not requested_path.exists():
        return f"Error: File not found: {file_path}"

    parsed = _parse_linux_auth_log_data(requested_path)
    failed_logins = parsed["failed_logins"]
    successful_logins = parsed["successful_logins"]
    source_ips = parsed["source_ips"]
    users = parsed["users"]
    event_count = parsed["event_count"]

    summary = (
        f"Parsed {event_count} SSH auth event(s) from {file_path}: "
        f"{len(failed_logins)} failed login(s), "
        f"{len(successful_logins)} successful login(s), "
        f"{len(source_ips)} unique source IP(s), "
        f"{len(users)} unique user(s)."
    )

    result = {
        "status": "ok",
        "event_count": event_count,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "source_ips": source_ips,
        "users": users,
        "summary": summary,
        "analyst_note": (
            "This tool extracts facts from local Linux auth logs only. "
            "Review failed_logins and successful_logins for brute-force patterns, "
            "success-after-failure sequences, and unexpected source IPs. "
            "The AI should determine severity, confidence, and next steps. "
            "No SSH commands or API calls are run from this MCP server."
        ),
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def analyze_linux_auth_activity(file_path: str) -> str:
    """
    Analyze parsed Linux SSH/auth log activity from a local telemetry sample
    and produce SOC-style triage guidance. Reuses parse_linux_auth_log parsing
    logic and generate_investigation_runbook. No SSH commands or API calls.

    Returns investigation_runbook alongside risk scoring and parsed activity.
    """
    requested_path = (LAB_ROOT / file_path).resolve()

    if not str(requested_path).startswith(str(LAB_ROOT)):
        return "Error: File path is outside the allowed lab directory."

    if not requested_path.exists():
        return f"Error: File not found: {file_path}"

    parsed = _parse_linux_auth_log_data(requested_path)

    failed_count = len(parsed["failed_logins"])
    success_count = len(parsed["successful_logins"])
    source_ip_count = len(parsed["source_ips"])
    user_count = len(parsed["users"])
    success_after_failure = bool(parsed["success_after_failure_ips"])
    only_publickey_success = (
        failed_count == 0
        and success_count > 0
        and all(
            login.get("auth_method") == "publickey"
            for login in parsed["successful_logins"]
        )
    )

    confidence_score = 20
    scoring_notes: list[str] = ["Base confidence: 20 (SSH auth log review)."]

    if failed_count >= 10:
        confidence_score += 30
        scoring_notes.append(
            f"+30: {failed_count} failed login(s) observed (possible brute force)."
        )

    if success_after_failure:
        confidence_score += 25
        scoring_notes.append(
            "+25: successful login after prior failure from the same source IP "
            f"({', '.join(parsed['success_after_failure_ips'])})."
        )

    if source_ip_count > 1:
        confidence_score += 15
        scoring_notes.append(
            f"+15: {source_ip_count} unique source IP(s) (distributed activity)."
        )

    if only_publickey_success:
        confidence_score -= 10
        scoring_notes.append(
            "-10: zero failed logins and only publickey successful logins "
            "(often expected admin access)."
        )

    confidence_score = max(0, min(100, confidence_score))

    if confidence_score <= 39:
        risk_level = "low"
    elif confidence_score <= 69:
        risk_level = "medium"
    else:
        risk_level = "high"

    findings: list[str] = [
        f"Parsed {parsed['event_count']} SSH auth event(s) from {file_path}.",
        f"Failed logins: {failed_count}.",
        f"Successful logins: {success_count}.",
        f"Unique source IPs: {source_ip_count} ({', '.join(parsed['source_ips']) or 'none'}).",
        f"Unique users: {user_count} ({', '.join(parsed['users']) or 'none'}).",
    ]

    if failed_count == 0:
        findings.append("No failed login pattern observed.")
    elif failed_count < 10:
        findings.append(
            f"Failed login volume is below the brute-force threshold ({failed_count} < 10)."
        )
    else:
        findings.append(
            f"Failed login volume meets or exceeds the brute-force threshold ({failed_count} >= 10)."
        )

    if only_publickey_success:
        findings.append("Successful publickey logins only; no password failures in sample.")

    if success_after_failure:
        findings.append(
            "Success-after-failure activity detected from at least one source IP."
        )
    else:
        findings.append("No success-after-failure sequence detected in log order.")

    if risk_level == "low":
        recommended_actions = [
            "Continue routine monitoring and log the sample for baseline context.",
            f"Verify source IP(s) {', '.join(parsed['source_ips']) or 'N/A'} are expected for this host.",
            "Confirm publickey-based access aligns with your SSH hardening policy.",
            "Re-run analysis if new auth telemetry is collected or failure volume increases.",
        ]
    elif risk_level == "medium":
        recommended_actions = [
            "Search for additional failed logins from the same source IP(s) in a wider time window.",
            "Correlate successful logins with asset inventory and expected admin jump hosts.",
            "Review whether password authentication should be disabled if only keys are intended.",
            "Document findings and reassess if success-after-failure or failure volume grows.",
        ]
    else:
        recommended_actions = [
            "Escalate for senior analyst review; treat as potential unauthorized access.",
            "Preserve auth logs and review active sessions on the affected host.",
            "Investigate source IP(s) involved in success-after-failure sequences immediately.",
            "Consider blocking or restricting source IP(s) if unauthorized access is confirmed.",
        ]

    analyst_notes = (
        f"{' '.join(scoring_notes)} "
        f"Risk level: {risk_level} (confidence {confidence_score}/100). "
    )
    if only_publickey_success and failed_count == 0:
        analyst_notes += (
            "This sample looks like routine key-based access with no failure noise; "
            "still validate the source IP against your expected admin inventory."
        )
    elif success_after_failure:
        analyst_notes += (
            "Success after failure from the same IP is a high-value signal; "
            "correlate with firewall, EDR, and command history if available."
        )
    else:
        analyst_notes += (
            "Expand context with surrounding log lines and host criticality before closing."
        )

    parsed_activity = {
        "failed_login_count": failed_count,
        "successful_login_count": success_count,
        "unique_source_ip_count": source_ip_count,
        "unique_user_count": user_count,
        "success_after_failure": success_after_failure,
        "success_after_failure_ips": parsed["success_after_failure_ips"],
        "only_publickey_success": only_publickey_success,
        "source_ips": parsed["source_ips"],
        "users": parsed["users"],
        "failed_logins": parsed["failed_logins"],
        "successful_logins": parsed["successful_logins"],
    }

    result = {
        "status": "ok",
        "risk_level": risk_level,
        "confidence_score": confidence_score,
        "findings": findings,
        "recommended_actions": recommended_actions,
        "analyst_notes": analyst_notes,
        "parsed_activity": parsed_activity,
    }

    runbook = json.loads(
        generate_investigation_runbook(
            alert_type="linux_auth_activity",
            severity=risk_level,
            confidence_score=confidence_score,
        )
    )
    result["investigation_runbook"] = runbook

    return json.dumps(result, indent=2)


COMMAND_EXECUTION_INDICATORS = [
    "curl",
    "wget",
    "| bash",
    "bash -c",
    "powershell",
    "-enc",
    "encodedcommand",
    "certutil",
]

SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}


def _sigma_level_from_severity(severity: str) -> str:
    level = severity.lower()
    if level in SIGMA_LEVELS:
        return level
    return "medium"


def _format_sigma_tags(mitre_techniques: list[str]) -> str:
    if not mitre_techniques:
        return ""

    tag_lines = []
    for technique in mitre_techniques:
        normalized = technique.strip().lower()
        if normalized.startswith("attack."):
            tag_lines.append(f"    - {normalized}")
        else:
            technique_id = normalized.lstrip("t")
            tag_lines.append(f"    - attack.t{technique_id}")

    return "tags:\n" + "\n".join(tag_lines)


MITRE_TECHNIQUE_NAMES = {
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1105": "Ingress Tool Transfer",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1027": "Obfuscated Files or Information",
    "T1140": "Deobfuscate/Decode Files or Information",
}

DEFAULT_MITRE_BY_ALERT_TYPE = {
    "ssh_auth_failure": ["T1110", "T1078"],
    "linux_auth_activity": ["T1078"],
    "suspicious_command_execution": ["T1105", "T1059", "T1027"],
}

ATTACK_CHAIN_STAGE_BY_EVENT_TYPE = {
    "ssh_auth_failure": "Initial Access",
    "linux_auth_activity": "Valid Accounts",
    "suspicious_command_execution": "Command Execution",
}


def _normalize_technique_id(technique: str) -> str:
    normalized = technique.strip().lower()
    if normalized.startswith("attack."):
        normalized = normalized[7:]
    if normalized.startswith("t"):
        return normalized.upper()
    return "T" + normalized.upper()


def _mitre_technique_name(technique_id: str) -> str:
    return MITRE_TECHNIQUE_NAMES.get(technique_id, technique_id)


def _build_mitre_mapping(
    alert_type: str,
    mitre_techniques: list[str] | None = None,
) -> list[dict]:
    if mitre_techniques is None:
        mitre_techniques = []

    defaults = DEFAULT_MITRE_BY_ALERT_TYPE.get(alert_type, [])
    seen: set[str] = set()
    mapping: list[dict] = []

    for tech in defaults + mitre_techniques:
        technique_id = _normalize_technique_id(tech)
        if technique_id in seen:
            continue
        seen.add(technique_id)
        mapping.append(
            {
                "technique_id": technique_id,
                "name": _mitre_technique_name(technique_id),
            }
        )

    return mapping


def _build_engineering_summary(
    alert_type: str,
    severity: str,
    confidence_score: int,
    mitre_techniques: list[str],
    detection_recommendations: dict,
    sigma_rule: dict,
    sentinel_rule: dict | None = None,
    qradar_rule: dict | None = None,
) -> dict:
    gaps = detection_recommendations.get("detection_gaps", [])
    if gaps:
        gap_list = "; ".join(gaps)
        detection_gap_summary = (
            f"For alert type '{alert_type}', current detection gaps include: {gap_list}."
        )
    else:
        detection_gap_summary = (
            f"No specific detection gaps were listed for alert type '{alert_type}'."
        )

    mitre_coverage = detection_recommendations.get("mitre_coverage", [])
    coverage_text = ", ".join(mitre_coverage) if mitre_coverage else "none listed"
    if mitre_techniques:
        mapped = ", ".join(mitre_techniques)
        mitre_coverage_summary = (
            f"Recommended MITRE coverage: {coverage_text}. "
            f"Investigation mapped techniques: {mapped}."
        )
    else:
        mitre_coverage_summary = f"Recommended MITRE coverage: {coverage_text}."

    recommended_engineering_actions = (
        detection_recommendations.get("recommended_detections", [])
        + detection_recommendations.get("telemetry_recommendations", [])
        + detection_recommendations.get("engineering_notes", [])
    )

    sigma_note = sigma_rule.get("analyst_note", "")
    sentinel_note = ""
    if sentinel_rule and sentinel_rule.get("kql"):
        rule_name = sentinel_rule.get("rule_name", "Sentinel rule")
        sentinel_note = (
            f" A Sentinel analytic rule draft ({rule_name}) is also included "
            "in this package; paste its KQL into Azure Sentinel Analytics."
        )

    qradar_note = ""
    if qradar_rule and qradar_rule.get("aql"):
        rule_name = qradar_rule.get("rule_name", "QRadar rule")
        qradar_note = (
            f" A QRadar AQL detection draft ({rule_name}) is also included "
            "in this package; paste its AQL into QRadar Log Activity or a Custom Rule."
        )

    if sigma_rule.get("status") == "error":
        analyst_note = (
            f"{sigma_note} Detection recommendations are still included in this package, "
            "but no Sigma rule draft was generated for this alert type."
            f"{sentinel_note}{qradar_note} "
            f"Case context: {severity} severity, confidence {confidence_score}/100."
        )
    else:
        analyst_note = (
            f"{sigma_note}{sentinel_note}{qradar_note} Case context: {severity} severity, "
            f"confidence {confidence_score}/100. Review and tune before deployment."
        )

    return {
        "detection_gap_summary": detection_gap_summary,
        "mitre_coverage_summary": mitre_coverage_summary,
        "recommended_engineering_actions": recommended_engineering_actions,
        "analyst_note": analyst_note,
    }


@mcp.tool()
def identify_alert_type(file_path: str) -> str:
    """
    Classify a Wazuh alert and recommend the correct investigation workflow.
    Reads the alert JSON file and inspects rule, decoder, full_log, and
    common command-related fields. No API calls.

    Supported routes:
    - ssh_auth_failure -> investigate_ssh_alert
    - suspicious_command_execution -> investigate_command_execution
    - unknown -> manual_review
    """
    requested_path = (LAB_ROOT / file_path).resolve()

    if not str(requested_path).startswith(str(LAB_ROOT)):
        return "Error: File path is outside the allowed lab directory."

    if not requested_path.exists():
        return f"Error: File not found: {file_path}"

    with open(requested_path, "r") as f:
        alert = json.load(f)

    rule = alert.get("rule", {})
    decoder = alert.get("decoder", {})
    data = alert.get("data", {})
    full_log = alert.get("full_log", "")

    rule_id = rule.get("id")
    rule_description = rule.get("description", "")
    decoder_name = decoder.get("name", "")

    command = alert.get("command", "")
    data_command = data.get("command", "")
    data_audit_command = data.get("audit", {}).get("command", "")
    data_win_command_line = data.get("win", {}).get("eventdata", {}).get("commandLine", "")

    detected_fields = {
        "rule_id": rule_id,
        "rule_description": rule_description,
        "decoder_name": decoder_name,
        "full_log": full_log,
        "command": command,
        "data_command": data_command,
        "data_audit_command": data_audit_command,
        "data_win_command_line": data_win_command_line,
    }

    ssh_matches = []
    if "sshd" in decoder_name.lower():
        ssh_matches.append("decoder.name contains 'sshd'")
    if "ssh" in rule_description.lower():
        ssh_matches.append("rule.description contains 'ssh'")
    if "Failed password" in full_log:
        ssh_matches.append("full_log contains 'Failed password'")

    if ssh_matches:
        result = {
            "status": "ok",
            "alert_type": "ssh_auth_failure",
            "recommended_workflow": "investigate_ssh_alert",
            "confidence": "high",
            "reasoning": (
                "Alert matched SSH authentication failure indicators: "
                + "; ".join(ssh_matches)
                + ". Use investigate_ssh_alert for the full triage workflow."
            ),
            "detected_fields": detected_fields,
        }
    else:
        searchable_sources = {
            "full_log": full_log,
            "rule.description": rule_description,
            "command": command,
            "data.command": data_command,
            "data.audit.command": data_audit_command,
            "data.win.eventdata.commandLine": data_win_command_line,
        }

        cmd_matches = []
        for field_name, field_value in searchable_sources.items():
            if not field_value:
                continue
            field_lower = field_value.lower()
            for indicator in COMMAND_EXECUTION_INDICATORS:
                if indicator in field_lower:
                    cmd_matches.append(f"{field_name} contains '{indicator}'")

        if cmd_matches:
            result = {
                "status": "ok",
                "alert_type": "suspicious_command_execution",
                "recommended_workflow": "investigate_command_execution",
                "confidence": "medium",
                "reasoning": (
                    "Alert matched suspicious command execution indicators: "
                    + "; ".join(cmd_matches)
                    + ". Use investigate_command_execution for the full triage workflow."
                ),
                "detected_fields": detected_fields,
            }
        else:
            result = {
                "status": "ok",
                "alert_type": "unknown",
                "recommended_workflow": "manual_review",
                "confidence": "low",
                "reasoning": (
                    "No known alert type matched. SSH indicators (sshd decoder, "
                    "ssh in rule description, Failed password in full_log) and "
                    "command-execution indicators (curl, wget, bash piping, "
                    "powershell, encoded commands, certutil) were checked in "
                    "full_log, rule.description, and command-related fields. "
                    "Manual analyst review is recommended."
                ),
                "detected_fields": detected_fields,
            }

    return json.dumps(result, indent=2)


@mcp.tool()
def score_ssh_alert(
    source_ip: str,
    target_user: str,
    rule_level: int,
    source_is_known_admin_host: bool = False,
    failures_last_10_minutes: int = 1,
    success_after_failure: bool = False,
) -> str:
    """
    Score an SSH failed-login alert using simple rule-based logic.
    Returns severity, confidence, priority, reasoning, and next steps.
    """
    confidence = 40
    reasoning_parts = [
        "Base confidence: 40 (SSH failed login alert).",
        f"Source IP: {source_ip}, target user: {target_user}, Wazuh rule level: {rule_level}.",
    ]

    if target_user == "root":
        confidence += 20
        reasoning_parts.append("+20: target user is root (high-value account).")

    if failures_last_10_minutes >= 10:
        confidence += 20
        reasoning_parts.append(
            f"+20: {failures_last_10_minutes} failures in the last 10 minutes "
            "(possible brute-force activity)."
        )

    if success_after_failure:
        confidence += 30
        reasoning_parts.append(
            "+30: successful login after prior failures (possible compromise)."
        )

    if source_is_known_admin_host:
        confidence -= 15
        reasoning_parts.append(
            "-15: source is a known admin host (activity may be expected)."
        )

    confidence = max(0, min(100, confidence))

    if confidence <= 39:
        severity = "low"
        priority = "P4"
        recommended_next_steps = [
            "Log the alert and continue routine monitoring.",
            "Re-check if failures from this source increase over the next hour.",
        ]
    elif confidence <= 69:
        severity = "medium"
        priority = "P3"
        recommended_next_steps = [
            "Search recent auth logs for the same source_ip and target_user.",
            "Correlate with other alerts from the same host in the last 24 hours.",
            "Confirm whether the source IP is expected for this environment.",
        ]
    else:
        severity = "high"
        priority = "P2"
        recommended_next_steps = [
            "Escalate to a senior analyst immediately.",
            "Review active sessions and recent commands on the affected host.",
            "Consider blocking source_ip at the firewall if policy allows.",
            "If success_after_failure is true, treat as a potential incident and preserve logs.",
        ]

    result = {
        "severity": severity,
        "confidence_score": confidence,
        "priority": priority,
        "reasoning": " ".join(reasoning_parts),
        "recommended_next_steps": recommended_next_steps,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_wazuh_query(
    source_ip: str,
    agent_name: str,
    rule_id: str = "5710",
    hours_back: int = 24,
) -> str:
    """
    Generate beginner-friendly Wazuh/OpenSearch query examples for
    SSH failed-login investigations. Returns query text only (no API calls).
    """
    time_window = f"now-{hours_back}h"

    opensearch_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"rule.id": rule_id}},
                    {"term": {"agent.name": agent_name}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": time_window,
                                "lte": "now",
                            }
                        }
                    },
                ],
                "should": [
                    {"term": {"srcip": source_ip}},
                    {"term": {"data.srcip": source_ip}},
                ],
                "minimum_should_match": 1,
            }
        },
    }

    simple_filter = (
        f'rule.id:{rule_id} AND agent.name:"{agent_name}" AND '
        f'(srcip:{source_ip} OR data.srcip:{source_ip}) AND '
        f"@timestamp:[{time_window} TO now]"
    )

    description = (
        f"OpenSearch query to find SSH failed-login alerts (rule {rule_id}) "
        f"from source IP {source_ip} on agent {agent_name} in the last {hours_back} hours."
    )

    analyst_note = (
        "This tool only builds example query text for learning and manual use. "
        "Paste it into Wazuh/OpenSearch Dashboards (Discover or Dev Tools). "
        "Wazuh may store the source IP in srcip or data.srcip depending on the alert, "
        "so the query checks both fields. Adjust field names if your index mapping differs. "
        "No searches are run automatically from this MCP server."
    )

    result = {
        "status": "ok",
        "description": description,
        "opensearch_query": opensearch_query,
        "simple_filter": simple_filter,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_defender_kql(
    source_ip: str,
    device_name: str,
    target_user: str = "root",
    hours_back: int = 24,
) -> str:
    """
    Generate beginner-friendly Microsoft Defender Advanced Hunting and
    Azure Sentinel KQL examples for SSH failed-login investigations.
    Returns query text only (no API calls, no destructive actions).
    """
    defender_kql = f"""DeviceNetworkEvents
| where Timestamp >= ago({hours_back}h)
| where DeviceName =~ "{device_name}"
| where RemotePort == 22 or LocalPort == 22
| where RemoteIP == "{source_ip}" or LocalIP == "{source_ip}"
| project Timestamp, DeviceName, ActionType, RemoteIP, LocalIP, RemotePort, LocalPort"""

    sentinel_syslog_kql = f"""Syslog
| where TimeGenerated >= ago({hours_back}h)
| where SyslogMessage contains "Failed password"
| where SyslogMessage contains "{target_user}"
| where SyslogMessage contains "{source_ip}"
| project TimeGenerated, Computer, SyslogMessage"""

    description = (
        f"KQL examples to hunt SSH failed logins from {source_ip} "
        f"on {device_name} for user {target_user} in the last {hours_back} hours."
    )

    analyst_note = (
        "This tool only builds example query text for learning and manual use. "
        "Paste defender_kql into Microsoft Defender Advanced hunting, "
        "and sentinel_syslog_kql into Azure Sentinel or Log Analytics (Logs). "
        "Defender checks network events on port 22; Sentinel checks Linux auth "
        "syslog lines containing 'Failed password'. "
        "Adjust table or field names if your tenant uses different schemas. "
        "No searches are run automatically from this MCP server."
    )

    result = {
        "status": "ok",
        "description": description,
        "defender_kql": defender_kql,
        "sentinel_syslog_kql": sentinel_syslog_kql,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_investigation_summary(
    source_ip: str,
    target_user: str,
    host: str,
    rule_id: str,
    rule_description: str,
    severity: str,
    confidence_score: int,
    priority: str,
) -> str:
    """
    Generate a SOC-style investigation summary from alert observables and
    scoring information. Returns structured JSON only (no API calls).
    """
    executive_summary = (
        f"An SSH authentication failure was observed for user {target_user} "
        f"on host {host}, sourced from {source_ip}. "
        f"Wazuh rule {rule_id} ({rule_description}) generated this alert. "
        f"The case is rated {severity} severity with confidence {confidence_score} "
        f"and assigned priority {priority} for analyst review."
    )

    observables = {
        "source_ip": source_ip,
        "target_user": target_user,
        "host": host,
        "rule_id": rule_id,
        "rule_description": rule_description,
    }

    severity_key = severity.lower()
    if severity_key == "low":
        severity_sentence = (
            f"The alert is classified as low severity ({priority}), "
            "suggesting routine monitoring and limited immediate impact."
        )
    elif severity_key == "medium":
        severity_sentence = (
            f"The alert is classified as medium severity ({priority}), "
            "warranting targeted investigation and correlation within the environment."
        )
    else:
        severity_sentence = (
            f"The alert is classified as high severity ({priority}), "
            "requiring prompt analyst attention and potential escalation."
        )

    if confidence_score <= 39:
        confidence_sentence = (
            f"Confidence is {confidence_score}/100 (low), indicating limited "
            "corroborating indicators and a higher chance of benign or incomplete context."
        )
    elif confidence_score <= 69:
        confidence_sentence = (
            f"Confidence is {confidence_score}/100 (moderate), indicating some "
            "supporting indicators but remaining uncertainty without additional telemetry."
        )
    else:
        confidence_sentence = (
            f"Confidence is {confidence_score}/100 (high), indicating multiple "
            "supporting indicators that increase concern for malicious or unauthorized activity."
        )

    rule_sentence = (
        f"Rule {rule_id} ({rule_description}) fired for this authentication event."
    )
    if target_user == "root":
        rule_sentence += (
            " The target account is root, a high-value identity that elevates "
            "potential impact if access is gained."
        )

    risk_assessment = " ".join(
        [severity_sentence, confidence_sentence, rule_sentence]
    )

    if severity_key == "low":
        recommended_actions = [
            "Continue routine monitoring and log the alert for trend analysis.",
            f"Verify whether source IP {source_ip} is an expected origin for SSH access to {host}.",
            "Baseline recent authentication failures for the same target_user over the past 24 hours.",
            (
                "Use generate_wazuh_query or generate_defender_kql to build manual hunt queries "
                "if failure volume increases."
            ),
        ]
    elif severity_key == "medium":
        recommended_actions = [
            (
                f"Search authentication and security logs for additional events from "
                f"{source_ip} targeting {target_user} on {host}."
            ),
            (
                "Use generate_wazuh_query and generate_defender_kql to produce hunt queries, "
                "then run them manually in your SIEM dashboards."
            ),
            f"Review other alerts involving host {host} in the last 24 hours for correlation.",
            (
                f"Confirm whether {source_ip} is authorized for administrative access "
                f"to {target_user} on this system."
            ),
            "Document findings and reassess severity if new failures or successes appear.",
        ]
    else:
        recommended_actions = [
            f"Escalate per {priority} procedures and assign a senior analyst immediately.",
            (
                f"Review active sessions, recent logins, and command history on {host} "
                f"for user {target_user}."
            ),
            (
                "Use generate_wazuh_query and generate_defender_kql to hunt related activity, "
                "then execute queries manually in Wazuh/OpenSearch and Defender/Sentinel."
            ),
            (
                f"Evaluate containment options for source IP {source_ip} if policy permits "
                "and unauthorized access is suspected."
            ),
            "Preserve relevant logs and artifacts for potential incident response.",
        ]

    recommended_actions = recommended_actions[:5]

    if confidence_score <= 39:
        analyst_notes = (
            "Additional telemetry would materially improve confidence: authentication "
            "failure counts within a defined time window, asset criticality for the host, "
            "geo/ASN context for the source IP, and whether the source is a known jump host. "
            "Context such as success-after-failure events and elevated failure rates "
            "(as used by score_ssh_alert) would also sharpen the assessment."
        )
    elif confidence_score <= 69:
        analyst_notes = (
            "Confidence would benefit from correlating events across agents and hosts, "
            "netflow or firewall telemetry on port 22, and EDR process lineage after "
            "authentication attempts. "
            "Success-after-failure indicators and failure-rate trends over the last "
            "10 minutes would align scoring with observed attack patterns."
        )
    else:
        analyst_notes = (
            "Even at elevated confidence, validating post-authentication command execution, "
            "persistence indicators, and lateral movement telemetry would confirm or deny "
            "active compromise. "
            "Cross-check success-after-failure and brute-force volume signals to ensure "
            "the score reflects the full attack timeline."
        )

    result = {
        "executive_summary": executive_summary,
        "observables": observables,
        "risk_assessment": risk_assessment,
        "recommended_actions": recommended_actions,
        "analyst_notes": analyst_notes,
    }

    return json.dumps(result, indent=2)


SUPPORTED_RUNBOOK_ALERT_TYPES = {
    "ssh_auth_failure",
    "suspicious_command_execution",
    "linux_auth_activity",
    "unknown",
}


@mcp.tool()
def generate_investigation_runbook(
    alert_type: str,
    severity: str = "medium",
    confidence_score: int = 60,
) -> str:
    """
    Generate a reusable SOC investigation runbook based on alert type, severity,
    and confidence score. Returns structured JSON only (no API calls, SSH, or
    external lookups).
    """
    severity_key = severity.lower()
    unrecognized_note = ""

    if alert_type not in SUPPORTED_RUNBOOK_ALERT_TYPES:
        unrecognized_note = (
            f"Input alert_type '{alert_type}' is not recognized; "
            "using the generic unknown alert runbook. "
        )
        effective_alert_type = "unknown"
    else:
        effective_alert_type = alert_type

    if confidence_score <= 39:
        confidence_label = "low"
    elif confidence_score <= 69:
        confidence_label = "moderate"
    else:
        confidence_label = "high"

    if effective_alert_type == "ssh_auth_failure":
        runbook_title = "SSH Authentication Failure Investigation Runbook"
        purpose = (
            "Guide analysts through triage of SSH authentication failure alerts, "
            "including brute-force validation and success-after-failure review."
        )
        required_inputs = [
            "Source IP address",
            "Target username",
            "Host or agent name",
            "Rule ID and rule description (if from SIEM)",
            "Failed login count in a defined time window",
            "Whether a successful login followed failures from the same source IP",
            "Whether the source IP is a known admin or jump host",
        ]
        investigation_steps = [
            "Review failed login events for volume, timing, and targeted accounts.",
            "Analyze the source IP for prior activity, geo context, and reputation (manual).",
            "Review the target account for privilege level, expected access, and lockout status.",
            "Determine whether root or other high-value accounts were targeted.",
            "Validate brute-force patterns (for example, >=10 failures in 10 minutes).",
            "Check for successful login after repeated failures from the same source IP.",
            "Confirm whether the source IP matches known admin or jump host inventory.",
            "Correlate SSH auth logs with SIEM alerts and EDR process activity on the host.",
        ]
        recommended_mcp_tools = [
            "parse_wazuh_alert",
            "score_ssh_alert",
            "investigate_ssh_alert",
            "generate_wazuh_query",
            "generate_defender_kql",
            "generate_investigation_summary",
            "generate_soc_ticket_note",
            "generate_detection_recommendation",
        ]
        detection_engineering_opportunities = [
            "Brute-force correlation (multiple failures in a short window)",
            "Success-after-failure detection from the same source IP",
            "Root login from uncommon source IP",
            "Threshold-based SSH failure alerting tuned to your environment",
        ]
        ticket_documentation_guidance = [
            "Document source IP, target user, host, and rule metadata.",
            "Record failed login count and time window used for brute-force assessment.",
            "Note whether success-after-failure or known admin host context applies.",
            "Capture SIEM/EDR correlation findings and final disposition.",
        ]
    elif effective_alert_type == "suspicious_command_execution":
        runbook_title = "Suspicious Command Execution Investigation Runbook"
        purpose = (
            "Guide analysts through review of suspicious command-line activity, "
            "including download-and-execute and obfuscation patterns."
        )
        required_inputs = [
            "Full command line or process arguments",
            "Username that executed the command",
            "Hostname or device name",
            "Parent process name and command line",
            "Timestamp of execution",
            "Source IP or session context (if available)",
        ]
        investigation_steps = [
            "Review the full command line for download tools, pipes, encoding, or obfuscation.",
            "Review the user account for role, expected activity, and recent privilege changes.",
            "Review the host for asset criticality, patch level, and prior alerts.",
            "Review the parent process for unexpected launchers (for example, office apps spawning shells).",
            "Check for download-and-execute patterns (curl/wget piped to bash or similar).",
            "Review PowerShell usage for encoded commands or suspicious flags.",
            "Review certutil usage for download, decode, or cache abuse.",
            "Review network connections around the execution time for C2 or payload retrieval.",
            "Map observed behavior to MITRE ATT&CK techniques for reporting and detection gaps.",
        ]
        recommended_mcp_tools = [
            "investigate_command_execution",
            "generate_defender_kql",
            "generate_detection_recommendation",
            "generate_sigma_rule",
            "generate_detection_package",
        ]
        detection_engineering_opportunities = [
            "Download-and-execute command-line detections (curl/wget + shell)",
            "PowerShell encoded command monitoring",
            "Certutil abuse detections",
            "Parent-child process anomaly rules for suspicious interpreters",
        ]
        ticket_documentation_guidance = [
            "Document the full command line, user, host, and parent process.",
            "List matched suspicious indicators and MITRE techniques.",
            "Record hunt query results and any confirmed malicious artifacts.",
            "Document containment actions taken and escalation rationale.",
        ]
    elif effective_alert_type == "linux_auth_activity":
        runbook_title = "Linux Auth Activity Investigation Runbook"
        purpose = (
            "Guide analysts through review of Linux SSH/auth log samples for "
            "failed logins, successful access, and hardening validation."
        )
        required_inputs = [
            "Auth log file path or exported sample",
            "Time range covered by the sample",
            "Host identity and criticality",
            "Expected admin source IPs or jump hosts",
            "SSH authentication policy (password vs publickey)",
        ]
        investigation_steps = [
            "Count failed login events and compare against brute-force thresholds.",
            "Count successful login events and identify authentication methods used.",
            "Review unique source IPs for expected vs unexpected origins.",
            "Review targeted usernames for privilege level and account validity.",
            "Validate whether successful logins used publickey only with zero password failures.",
            "Analyze success-after-failure sequences from the same source IP.",
            "Validate SSH hardening settings align with policy (for example, key-only access).",
        ]
        recommended_mcp_tools = [
            "parse_linux_auth_log",
            "analyze_linux_auth_activity",
            "generate_wazuh_query",
            "generate_detection_recommendation",
        ]
        detection_engineering_opportunities = [
            "Auth log threshold alerts for repeated failures",
            "Success-after-failure correlation from parsed auth telemetry",
            "Alerts for password auth when only publickey is intended",
            "Distributed SSH failure detection across multiple source IPs",
        ]
        ticket_documentation_guidance = [
            "Document failed and successful login counts from the parsed sample.",
            "List unique source IPs and users observed.",
            "Note success-after-failure or publickey-only patterns.",
            "Record hardening validation results and recommended follow-up.",
        ]
    else:
        runbook_title = "Generic SOC Investigation Runbook"
        purpose = (
            "Provide a baseline investigation workflow when the alert type is "
            "unknown or not yet classified."
        )
        required_inputs = [
            "Raw alert payload or log excerpt",
            "Timestamp and source system",
            "Host, user, and network observables available in the alert",
            "Any prior related tickets or alerts",
        ]
        investigation_steps = [
            "Collect all available observables from the alert and surrounding logs.",
            "Enrich the alert with host identity, user context, and asset criticality.",
            "Use classification guidance to map the alert to a known workflow if possible.",
            "Correlate the alert with related SIEM events in a wider time window.",
            "Document findings, disposition, and gaps for follow-up detection work.",
        ]
        recommended_mcp_tools = [
            "identify_alert_type",
            "parse_wazuh_alert",
            "generate_investigation_summary",
            "generate_soc_ticket_note",
        ]
        detection_engineering_opportunities = [
            "Document alert type and observables before building new rules",
            "Review existing SIEM rules for overlap or tuning opportunities",
            "Consider baseline behavioral detections once the alert is classified",
        ]
        ticket_documentation_guidance = [
            "Document raw observables and enrichment steps performed.",
            "Record classification outcome (known type vs still unknown).",
            "Capture SIEM correlation results and analyst disposition.",
            "Note telemetry gaps that blocked confident classification.",
        ]

    if severity_key == "high" or confidence_score >= 70:
        escalation_criteria = [
            "Escalate immediately when severity is high or confidence is elevated (>=70).",
            "Notify on-call or tier-2 per priority procedures.",
            "Assign a senior analyst if success-after-failure or active compromise is suspected.",
            "Preserve logs and artifacts before containment actions.",
        ]
    elif severity_key == "medium" or confidence_score >= 40:
        escalation_criteria = [
            "Escalate if additional corroborating events appear during investigation.",
            "Engage tier-2 when confidence reaches >=70 or severity increases.",
            "Continue targeted correlation before closing as benign.",
        ]
    else:
        escalation_criteria = [
            "Routine monitoring is acceptable when severity and confidence remain low.",
            "Escalate only if new failures, successes, or related alerts emerge.",
            "Reassess if observables change or enrichment raises confidence.",
        ]

    if effective_alert_type == "ssh_auth_failure":
        if severity_key == "high" or confidence_score >= 70:
            containment_considerations = [
                "Evaluate blocking the source IP at the firewall if unauthorized.",
                "Review active sessions on the target host for the affected user.",
                "Consider restricting SSH access or enforcing key-only authentication.",
                "Do not take destructive action without approval and evidence.",
            ]
        else:
            containment_considerations = [
                "Continue monitoring before containment unless policy requires action.",
                "Validate source IP against admin inventory before blocking.",
                "Review SSH hardening posture if repeated failures persist.",
            ]
    elif effective_alert_type == "suspicious_command_execution":
        if severity_key == "high" or confidence_score >= 70:
            containment_considerations = [
                "Evaluate host isolation if malicious download-and-execute is confirmed.",
                "Block related URLs, hashes, or IPs after validation.",
                "Preserve process, network, and file creation logs for IR.",
                "Do not isolate production systems without approval.",
            ]
        else:
            containment_considerations = [
                "Gather parent process and network context before containment.",
                "Confirm whether the command aligns with approved automation.",
                "Escalate containment decisions when confidence increases.",
            ]
    elif effective_alert_type == "linux_auth_activity":
        if severity_key == "high" or confidence_score >= 70:
            containment_considerations = [
                "Review active sessions immediately if success-after-failure is confirmed.",
                "Evaluate restricting source IPs involved in suspicious auth sequences.",
                "Preserve auth logs before making access policy changes.",
            ]
        else:
            containment_considerations = [
                "Validate publickey-only access policy before restricting users.",
                "Monitor for increasing failure volume before blocking sources.",
            ]
    else:
        containment_considerations = [
            "Preserve original alert data and related logs before making changes.",
            "Avoid containment until the alert is classified and validated.",
            "Escalate for IR guidance when impact or scope is unclear.",
        ]

    analyst_note = (
        f"{unrecognized_note}"
        f"Runbook tailored for {effective_alert_type} at {severity_key} severity "
        f"with {confidence_label} confidence ({confidence_score}/100). "
        "This is a reusable analyst playbook template; adapt steps to your "
        "environment and run SIEM/EDR queries manually. "
        "No actions are executed automatically from this MCP server."
    )

    result = {
        "status": "ok",
        "runbook_title": runbook_title,
        "alert_type": effective_alert_type,
        "purpose": purpose,
        "required_inputs": required_inputs,
        "investigation_steps": investigation_steps,
        "escalation_criteria": escalation_criteria,
        "containment_considerations": containment_considerations,
        "detection_engineering_opportunities": detection_engineering_opportunities,
        "recommended_mcp_tools": recommended_mcp_tools,
        "ticket_documentation_guidance": ticket_documentation_guidance,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_soc_ticket_note(
    source_ip: str,
    target_user: str,
    host: str,
    severity: str,
    confidence_score: int,
    priority: str,
    rule_id: str,
    rule_description: str,
    recommended_action: str,
) -> str:
    """
    Generate a clean SOC ticket note suitable for ServiceNow, Jira, or IBM SOAR.
    Returns structured JSON with a paste-ready ticket note (no API calls).
    """
    summary = (
        f"SSH authentication failure for user {target_user} on host {host}, "
        f"sourced from {source_ip}. Wazuh rule {rule_id} ({rule_description}) "
        f"triggered this alert."
    )

    observables_block = (
        f"- Source IP: {source_ip}\n"
        f"- Target User: {target_user}\n"
        f"- Host: {host}\n"
        f"- Rule ID: {rule_id}\n"
        f"- Rule Description: {rule_description}"
    )

    severity_key = severity.lower()
    if confidence_score <= 39:
        confidence_label = "low"
    elif confidence_score <= 69:
        confidence_label = "moderate"
    else:
        confidence_label = "high"

    severity_priority_block = (
        f"- Severity: {severity_key}\n"
        f"- Priority: {priority}\n"
        f"- Confidence Score: {confidence_score}/100 ({confidence_label})"
    )

    if severity_key == "low":
        analysis = (
            f"This alert indicates a failed SSH login attempt against {target_user} "
            f"on {host} from {source_ip}. Current severity is {severity_key} with "
            f"{confidence_label} confidence ({confidence_score}/100). "
            f"Single or isolated failures may reflect misconfiguration or routine "
            f"scanning; immediate compromise is unlikely without corroborating indicators."
        )
        next_steps = [
            "Continue monitoring for repeated failures from the same source IP.",
            f"Verify whether {source_ip} is an authorized origin for SSH access.",
            "Reassess priority if failure volume increases or a successful login follows.",
        ]
    elif severity_key == "medium":
        analysis = (
            f"Multiple indicators suggest this SSH failure warrants investigation. "
            f"User {target_user} on {host} was targeted from {source_ip} under "
            f"rule {rule_id}. Severity is {severity_key} with {confidence_label} "
            f"confidence ({confidence_score}/100). Correlation with other auth "
            f"events and asset context is needed before closing."
        )
        next_steps = [
            f"Search auth logs for additional events from {source_ip} on {host}.",
            "Correlate with other alerts on this host in the last 24 hours.",
            f"Confirm authorization for {source_ip} to access {target_user}.",
            "Update ticket severity if new evidence emerges.",
        ]
    else:
        analysis = (
            f"High-severity SSH authentication activity detected: {target_user} "
            f"on {host} from {source_ip}. Confidence is {confidence_label} "
            f"({confidence_score}/100) under rule {rule_id}. "
            f"Unauthorized access or active attack patterns may be in progress; "
            f"prompt validation and potential escalation are required."
        )
        next_steps = [
            f"Escalate per {priority} procedures and notify on-call if applicable.",
            f"Review active sessions and recent command history on {host}.",
            f"Evaluate blocking {source_ip} if unauthorized access is confirmed.",
            "Preserve logs and artifacts for potential incident response.",
        ]

    next_steps_block = "\n".join(f"- {step}" for step in next_steps)

    ticket_note = (
        f"1. SUMMARY\n"
        f"{summary}\n\n"
        f"2. OBSERVABLES\n"
        f"{observables_block}\n\n"
        f"3. SEVERITY / PRIORITY\n"
        f"{severity_priority_block}\n\n"
        f"4. ANALYSIS\n"
        f"{analysis}\n\n"
        f"5. RECOMMENDED ACTION\n"
        f"{recommended_action}\n\n"
        f"6. NEXT STEPS\n"
        f"{next_steps_block}"
    )

    analyst_note = (
        "This tool formats investigation findings into a paste-ready ticket note "
        "for ServiceNow, Jira, or IBM SOAR. Review and edit before submission; "
        "add timestamps, ticket IDs, and environment-specific context as needed. "
        "No tickets are created automatically from this MCP server."
    )

    result = {
        "status": "ok",
        "ticket_note": ticket_note,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def recommend_next_action(
    severity: str,
    confidence_score: int,
    priority: str,
) -> str:
    """
    Recommend the next investigative step based on alert severity and confidence.
    Returns structured JSON only (no API calls).
    """
    severity_key = severity.lower()

    if confidence_score >= 80:
        recommended_action = "Escalate and begin containment review"
    elif confidence_score >= 60:
        recommended_action = "Gather additional evidence"
    else:
        recommended_action = "Continue investigation before escalation"

    if severity_key == "high":
        recommended_tool = "generate_soc_ticket_note"
    elif confidence_score >= 80:
        recommended_tool = "generate_soc_ticket_note"
    elif confidence_score >= 60:
        recommended_tool = "generate_wazuh_query"
    else:
        recommended_tool = "generate_investigation_summary"

    if severity_key == "low":
        severity_sentence = (
            f"Severity is low ({priority}), so immediate escalation is usually not required."
        )
    elif severity_key == "medium":
        severity_sentence = (
            f"Severity is medium ({priority}), so targeted investigation is appropriate."
        )
    else:
        severity_sentence = (
            f"Severity is high ({priority}), so prompt analyst attention is warranted."
        )

    if confidence_score >= 80:
        confidence_sentence = (
            f"Confidence is {confidence_score}/100 (high), supporting escalation "
            "and containment review."
        )
    elif confidence_score >= 60:
        confidence_sentence = (
            f"Confidence is {confidence_score}/100 (moderate), so more telemetry "
            "should be collected before closing or escalating."
        )
    else:
        confidence_sentence = (
            f"Confidence is {confidence_score}/100 (low), so the case needs more "
            "investigation before escalation decisions."
        )

    reasoning = (
        f"{severity_sentence} {confidence_sentence} "
        f"Recommended action: {recommended_action}."
    )

    if severity_key == "high":
        analyst_guidance = (
            f"High severity ({priority}) with confidence {confidence_score}/100 means "
            "this case should be documented and handed off promptly. Use "
            "generate_soc_ticket_note to produce a paste-ready ticket note for "
            "ServiceNow, Jira, or SOAR, then follow your escalation playbook."
        )
    elif confidence_score >= 80:
        analyst_guidance = (
            f"Confidence {confidence_score}/100 crosses the escalation threshold even "
            f"at {severity_key} severity ({priority}). Begin containment review: "
            "validate active sessions, preserve logs, and use generate_soc_ticket_note "
            "to record findings for the incident queue."
        )
    elif confidence_score >= 60:
        analyst_guidance = (
            f"Confidence {confidence_score}/100 is moderate for {severity_key} severity "
            f"({priority}). Hunt for corroborating events before escalating. "
            "Use generate_wazuh_query (and generate_defender_kql if applicable) to "
            "build manual SIEM queries, then reassess severity and confidence."
        )
    else:
        analyst_guidance = (
            f"Confidence {confidence_score}/100 is still low for {severity_key} severity "
            f"({priority}). Expand context with parse_wazuh_alert, score_ssh_alert, "
            "and generate_investigation_summary to structure what is known so far. "
            "Escalate only if new evidence raises confidence or severity."
        )

    result = {
        "recommended_action": recommended_action,
        "reasoning": reasoning,
        "recommended_tool": recommended_tool,
        "analyst_guidance": analyst_guidance,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def investigate_ssh_alert(
    file_path: str,
    failures_last_10_minutes: int = 1,
    success_after_failure: bool = False,
    source_is_known_admin_host: bool = False,
) -> str:
    """
    Run a full SSH failed-login investigation from a Wazuh alert file:
    parse, score, summarize, generate hunt queries, and recommend the next
    analyst action. No API calls.
    Reuses parse_wazuh_alert, score_ssh_alert, generate_investigation_summary,
    generate_wazuh_query, generate_defender_kql, recommend_next_action,
    generate_detection_recommendation, and generate_investigation_runbook.

    Returns a complete SOC triage package:
    - alert_summary: parsed observables from the Wazuh alert file
    - risk_score: severity, confidence, priority, and reasoning
    - investigation_summary: executive summary and recommended actions
    - recommended_queries: Wazuh/OpenSearch and Defender/Sentinel KQL examples
    - next_action: recommended investigative step based on severity and confidence
    - detection_recommendations: post-investigation detection engineering guidance
    - investigation_runbook: reusable analyst runbook for this alert type

    Optional enrichment (passed to score_ssh_alert) improves scoring when the
    analyst has context beyond the alert file:
    - failures_last_10_minutes: +20 confidence when >= 10 (possible brute force)
    - success_after_failure: +30 confidence (possible compromise)
    - source_is_known_admin_host: -15 confidence (activity may be expected)
    """
    parsed_raw = parse_wazuh_alert(file_path)
    if parsed_raw.startswith("Error:"):
        return parsed_raw

    parsed = json.loads(parsed_raw)
    obs = parsed["observables"]

    scored = json.loads(
        score_ssh_alert(
            source_ip=obs["source_ip"],
            target_user=obs["target_user"],
            rule_level=obs["rule_level"],
            source_is_known_admin_host=source_is_known_admin_host,
            failures_last_10_minutes=failures_last_10_minutes,
            success_after_failure=success_after_failure,
        )
    )

    summary = json.loads(
        generate_investigation_summary(
            source_ip=obs["source_ip"],
            target_user=obs["target_user"],
            host=obs["host"],
            rule_id=str(obs["rule_id"]),
            rule_description=obs["rule_description"],
            severity=scored["severity"],
            confidence_score=scored["confidence_score"],
            priority=scored["priority"],
        )
    )

    wazuh_queries = json.loads(
        generate_wazuh_query(
            source_ip=obs["source_ip"],
            agent_name=obs["host"],
            rule_id=str(obs["rule_id"]),
        )
    )

    defender_queries = json.loads(
        generate_defender_kql(
            source_ip=obs["source_ip"],
            device_name=obs["host"],
            target_user=obs["target_user"],
        )
    )

    next_action = json.loads(
        recommend_next_action(
            severity=scored["severity"],
            confidence_score=scored["confidence_score"],
            priority=scored["priority"],
        )
    )

    detection_recommendations = json.loads(
        generate_detection_recommendation(
            alert_type="ssh_auth_failure",
            severity=scored["severity"],
            confidence_score=scored["confidence_score"],
        )
    )

    runbook = json.loads(
        generate_investigation_runbook(
            alert_type="ssh_auth_failure",
            severity=scored["severity"],
            confidence_score=scored["confidence_score"],
        )
    )

    result = {
        "alert_summary": parsed,
        "risk_score": scored,
        "investigation_summary": summary,
        "recommended_queries": {
            "wazuh_opensearch": wazuh_queries,
            "defender_sentinel": defender_queries,
        },
        "next_action": next_action,
        "detection_recommendations": detection_recommendations,
        "investigation_runbook": runbook,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def investigate_command_execution(
    command: str,
    hostname: str = "unknown",
    username: str = "unknown",
    source_ip: str = "unknown",
) -> str:
    """
    Analyze suspicious command execution activity such as curl, wget, bash,
    powershell, encoded commands, certutil, or payload download behavior.
    Returns structured JSON with scoring, MITRE mapping, hunt queries,
    analyst guidance, detection recommendations, and investigation runbook.
    No API calls. Reuses generate_detection_recommendation and
    generate_investigation_runbook.
    """
    if not command or not command.strip():
        return json.dumps(
            {
                "status": "error",
                "analyst_notes": "command is required and cannot be empty.",
            },
            indent=2,
        )

    command_lower = command.lower()
    confidence_score = 30
    suspicious_indicators = []
    mitre_entries = []

    def add_mitre(technique_id: str, name: str) -> None:
        for entry in mitre_entries:
            if entry["technique_id"] == technique_id:
                return
        mitre_entries.append({"technique_id": technique_id, "name": name})

    if "curl" in command_lower or "wget" in command_lower:
        confidence_score += 20
        suspicious_indicators.append("Remote download tool (curl/wget)")
        add_mitre("T1105", "Ingress Tool Transfer")

    if "| bash" in command_lower or "bash -c" in command_lower:
        confidence_score += 25
        suspicious_indicators.append("Piped or inline bash execution")
        add_mitre("T1059", "Command and Scripting Interpreter")

    if "powershell" in command_lower:
        confidence_score += 20
        suspicious_indicators.append("PowerShell interpreter invoked")
        add_mitre("T1059.001", "PowerShell")

    if "-enc" in command_lower or "encodedcommand" in command_lower:
        confidence_score += 25
        suspicious_indicators.append("Encoded/obfuscated command argument")
        add_mitre("T1027", "Obfuscated Files or Information")

    if "certutil" in command_lower:
        confidence_score += 20
        suspicious_indicators.append("certutil abuse for download/decode")
        add_mitre("T1105", "Ingress Tool Transfer")
        add_mitre("T1140", "Deobfuscate/Decode Files or Information")

    confidence_score = min(100, confidence_score)

    if confidence_score <= 39:
        severity = "low"
        priority = "P4"
    elif confidence_score <= 69:
        severity = "medium"
        priority = "P3"
    else:
        severity = "high"
        priority = "P2"

    if suspicious_indicators:
        indicator_text = ", ".join(suspicious_indicators).lower()
    else:
        indicator_text = "no high-risk command patterns detected"

    if hostname != "unknown" and username != "unknown":
        command_summary = (
            f"On host {hostname}, user {username} ran a command with "
            f"{indicator_text}."
        )
    elif hostname != "unknown":
        command_summary = (
            f"On host {hostname}, a command was executed with {indicator_text}."
        )
    elif username != "unknown":
        command_summary = (
            f"User {username} ran a command with {indicator_text}."
        )
    else:
        command_summary = f"A command was executed with {indicator_text}."

    query_snippet = command if len(command) <= 100 else command[:100]
    defender_filters = [
        f'ProcessCommandLine contains "{query_snippet}"',
    ]
    if hostname != "unknown":
        defender_filters.append(f'DeviceName =~ "{hostname}"')
    if username != "unknown":
        defender_filters.append(
            f'(AccountName =~ "{username}" or InitiatingProcessAccountName =~ "{username}")'
        )

    defender_kql = f"""DeviceProcessEvents
| where Timestamp >= ago(24h)
| where {" and ".join(defender_filters)}
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName, ProcessCommandLine, FileName"""

    sentinel_filters = [
        f'SyslogMessage contains "{query_snippet}"',
    ]
    if hostname != "unknown":
        sentinel_filters.append(f'Computer == "{hostname}"')
    if username != "unknown":
        sentinel_filters.append(f'SyslogMessage contains "{username}"')
    if source_ip != "unknown":
        sentinel_filters.append(f'SyslogMessage contains "{source_ip}"')

    sentinel_syslog_kql = f"""Syslog
| where TimeGenerated >= ago(24h)
| where {" and ".join(sentinel_filters)}
| project TimeGenerated, Computer, SyslogMessage"""

    if severity == "low":
        recommended_actions = [
            "Log the alert and continue routine monitoring.",
            "Verify whether the command is expected automation or admin activity.",
            "Re-check if the same command pattern appears again in the next 24 hours.",
        ]
    elif severity == "medium":
        recommended_actions = [
            f"Hunt for the same command on host {hostname} and user {username} in your SIEM.",
            "Review parent process and recent download activity on the affected host.",
            "Correlate with network logs for unexpected outbound connections.",
            "Confirm whether the command aligns with approved change or patch activity.",
        ]
    else:
        recommended_actions = [
            f"Escalate per {priority} procedures and notify on-call if applicable.",
            f"Review active sessions and process tree on {hostname} for follow-on activity.",
            "Preserve process, network, and file creation logs for incident response.",
            "Evaluate host isolation if unauthorized payload download or execution is confirmed.",
            "Block related URLs, hashes, or IPs if malicious intent is validated.",
        ]

    if confidence_score <= 39:
        confidence_note = (
            f"Confidence is {confidence_score}/100 (low). "
            "Few suspicious patterns matched; benign or incomplete context is possible."
        )
    elif confidence_score <= 69:
        confidence_note = (
            f"Confidence is {confidence_score}/100 (moderate). "
            "Some suspicious patterns matched; additional telemetry would sharpen the assessment."
        )
    else:
        confidence_note = (
            f"Confidence is {confidence_score}/100 (high). "
            "Multiple suspicious patterns stacked; treat as likely malicious until validated."
        )

    unknown_fields = []
    if hostname == "unknown":
        unknown_fields.append("hostname")
    if username == "unknown":
        unknown_fields.append("username")
    if source_ip == "unknown":
        unknown_fields.append("source_ip")

    if unknown_fields:
        enrichment_note = (
            f"Enrich missing fields ({', '.join(unknown_fields)}) from the original alert "
            "before closing the case."
        )
    else:
        enrichment_note = (
            "Hostname, username, and source IP were provided; use them to narrow hunt queries."
        )

    if suspicious_indicators:
        indicator_note = (
            f"Matched indicators: {'; '.join(suspicious_indicators)}. "
            "Overlapping rules stack (for example, curl piped to bash increases confidence)."
        )
    else:
        indicator_note = (
            "No rule-based suspicious patterns matched beyond the base command-execution context."
        )

    query_note = (
        "recommended_queries are example KQL for manual paste into Microsoft Defender "
        "Advanced Hunting and Azure Sentinel Log Analytics. "
    )
    if source_ip != "unknown":
        query_note += (
            f"For network correlation with source IP {source_ip}, also search "
            "DeviceNetworkEvents or firewall logs separately. "
        )
    query_note += "No searches are run automatically from this MCP server."

    analyst_notes = (
        f"{confidence_note} {indicator_note} {enrichment_note} {query_note}"
    )

    detection_recommendations = json.loads(
        generate_detection_recommendation(
            alert_type="suspicious_command_execution",
            severity=severity,
            confidence_score=confidence_score,
            mitre_techniques=[entry["technique_id"] for entry in mitre_entries],
        )
    )

    runbook = json.loads(
        generate_investigation_runbook(
            alert_type="suspicious_command_execution",
            severity=severity,
            confidence_score=confidence_score,
        )
    )

    result = {
        "status": "ok",
        "command_summary": command_summary,
        "suspicious_indicators": suspicious_indicators,
        "mitre_mapping": mitre_entries,
        "severity": severity,
        "confidence_score": confidence_score,
        "priority": priority,
        "recommended_queries": {
            "defender_kql": defender_kql,
            "sentinel_syslog_kql": sentinel_syslog_kql,
        },
        "recommended_actions": recommended_actions,
        "analyst_notes": analyst_notes,
        "detection_recommendations": detection_recommendations,
        "investigation_runbook": runbook,
    }

    return json.dumps(result, indent=2)


def _normalize_correlation_event(event: dict) -> dict:
    confidence_raw = event.get("confidence_score", 0)
    try:
        confidence_score = int(confidence_raw)
    except (TypeError, ValueError):
        confidence_score = 0

    event_type = str(event.get("event_type", "unknown")).strip().lower()
    severity = str(event.get("severity", "unknown")).strip().lower()

    return {
        "event_type": event_type,
        "timestamp": str(event.get("timestamp", "")).strip(),
        "source_ip": str(event.get("source_ip", "")).strip(),
        "host": str(event.get("host", "")).strip(),
        "username": str(event.get("username", "")).strip(),
        "severity": severity,
        "confidence_score": confidence_score,
        "description": str(event.get("description", "")).strip(),
    }


def _parse_event_timestamp(timestamp: str) -> datetime | None:
    if not timestamp:
        return None
    normalized = timestamp.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _event_sort_key(event: dict) -> tuple[int, float]:
    parsed = _parse_event_timestamp(event.get("timestamp", ""))
    if parsed is None:
        return (1, 0.0)
    return (0, parsed.timestamp())


def _events_share_source_ip(events: list[dict]) -> bool:
    ip_counts: dict[str, int] = {}
    for event in events:
        source_ip = event.get("source_ip", "")
        if not source_ip:
            continue
        ip_counts[source_ip] = ip_counts.get(source_ip, 0) + 1
    return any(count >= 2 for count in ip_counts.values())


def _events_share_host(events: list[dict]) -> bool:
    host_counts: dict[str, int] = {}
    for event in events:
        host = event.get("host", "")
        if not host:
            continue
        host_counts[host] = host_counts.get(host, 0) + 1
    return any(count >= 2 for count in host_counts.values())


def _events_are_linked(first: dict, second: dict) -> bool:
    first_ip = first.get("source_ip", "")
    second_ip = second.get("source_ip", "")
    if first_ip and first_ip == second_ip:
        return True
    first_host = first.get("host", "")
    second_host = second.get("host", "")
    return bool(first_host and first_host == second_host)


def _detect_event_sequence(
    events: list[dict],
    first_type: str,
    second_type: str,
) -> bool:
    sorted_events = sorted(events, key=_event_sort_key)

    for earlier in sorted_events:
        if earlier.get("event_type") != first_type:
            continue
        for later in sorted_events:
            if later is earlier:
                continue
            if later.get("event_type") != second_type:
                continue
            earlier_ts = _parse_event_timestamp(earlier.get("timestamp", ""))
            later_ts = _parse_event_timestamp(later.get("timestamp", ""))
            if earlier_ts and later_ts and earlier_ts >= later_ts:
                continue
            if _events_are_linked(earlier, later):
                return True
    return False


def _count_medium_confidence_events(events: list[dict]) -> int:
    return sum(1 for event in events if event.get("confidence_score", 0) >= 40)


def _build_attack_timeline(events: list[dict]) -> list[dict]:
    sorted_events = sorted(events, key=_event_sort_key)
    timeline: list[dict] = []
    for index, event in enumerate(sorted_events, start=1):
        timeline.append(
            {
                "step": index,
                "event_type": event.get("event_type", "unknown"),
                "timestamp": event.get("timestamp", ""),
                "source_ip": event.get("source_ip", ""),
                "host": event.get("host", ""),
                "username": event.get("username", ""),
                "description": event.get("description", ""),
            }
        )
    return timeline


def _build_possible_attack_chain(event_types_in_order: list[str]) -> list[str]:
    chain: list[str] = []
    seen: set[str] = set()
    for event_type in event_types_in_order:
        stage = ATTACK_CHAIN_STAGE_BY_EVENT_TYPE.get(event_type)
        if stage and stage not in seen:
            seen.add(stage)
            chain.append(stage)
    return chain


def _build_correlation_mitre_mapping(
    event_types_in_order: list[str],
    chain_detected: bool,
) -> list[dict]:
    if chain_detected:
        ordered_techniques = ["T1110", "T1078", "T1059"]
        return [
            {
                "technique_id": technique_id,
                "name": _mitre_technique_name(technique_id),
            }
            for technique_id in ordered_techniques
        ]

    seen: set[str] = set()
    mapping: list[dict] = []
    for event_type in event_types_in_order:
        for entry in _build_mitre_mapping(event_type):
            technique_id = entry["technique_id"]
            if technique_id in seen:
                continue
            seen.add(technique_id)
            mapping.append(entry)
    return mapping


def _risk_level_from_confidence(confidence_score: int) -> str:
    if confidence_score <= 39:
        return "low"
    if confidence_score <= 69:
        return "medium"
    return "high"


def _bump_risk_level(risk_level: str) -> str:
    if risk_level == "low":
        return "medium"
    if risk_level == "medium":
        return "high"
    return "high"


def _score_correlation(
    events: list[dict],
    same_source_ip: bool,
    same_host: bool,
    ssh_before_auth: bool,
    auth_before_command: bool,
    ssh_before_command: bool,
    medium_confidence_count: int,
) -> tuple[int, list[str]]:
    confidence_score = 30
    findings: list[str] = []

    if same_source_ip:
        confidence_score += 20
        findings.append(
            "Rule 1: The same source IP appears across multiple correlated events."
        )
    if same_host:
        confidence_score += 15
        findings.append(
            "Rule 2: The same host appears across multiple correlated events."
        )
    if ssh_before_auth:
        confidence_score += 20
        findings.append(
            "Rule 3: SSH authentication failures were followed by Linux auth activity."
        )
    if auth_before_command:
        confidence_score += 25
        findings.append(
            "Rule 4: Linux auth activity was followed by suspicious command execution."
        )
    if ssh_before_command:
        confidence_score += 15
        findings.append(
            "Rule 5: SSH authentication failures were followed by suspicious command execution."
        )
    if medium_confidence_count >= 2:
        confidence_score += 10
        findings.append(
            "Rule 6: Multiple medium-confidence events increase overall correlation confidence."
        )

    confidence_score = max(0, min(100, confidence_score))
    return confidence_score, findings


def _correlation_escalation_and_steps(
    risk_level: str,
) -> tuple[str, list[str]]:
    if risk_level == "high":
        return (
            "Escalate promptly and review containment options for the correlated activity.",
            [
                "Escalate",
                "Review containment options",
                "Generate SOC documentation",
            ],
        )
    if risk_level == "medium":
        return (
            "Expand the investigation and hunt for related activity before closing the case.",
            [
                "Expand investigation",
                "Hunt for related activity",
            ],
        )
    return (
        "Continue monitoring and gather additional telemetry before escalation.",
        [
            "Continue monitoring",
            "Gather additional telemetry",
        ],
    )


def _collect_related_events(
    events: list[dict],
    sequence_detected: bool,
) -> list[dict]:
    if not events:
        return []

    related_flags = [False] * len(events)
    for index, event in enumerate(events):
        for other_index, other in enumerate(events):
            if index == other_index:
                continue
            if _events_are_linked(event, other):
                related_flags[index] = True
                related_flags[other_index] = True

    if sequence_detected:
        related_flags = [True] * len(events)

    return [event for index, event in enumerate(events) if related_flags[index]]


def _build_correlation_detection_gaps(
    events: list[dict],
    ssh_before_auth: bool,
    auth_before_command: bool,
    ssh_before_command: bool,
) -> list[str]:
    event_types = {event.get("event_type") for event in events}
    gaps: list[str] = []

    if "ssh_auth_failure" in event_types and "suspicious_command_execution" not in event_types:
        gaps.append(
            "Missing command-line or EDR telemetry to confirm post-access execution."
        )
    if (
        "ssh_auth_failure" in event_types
        and "linux_auth_activity" not in event_types
        and "suspicious_command_execution" in event_types
        and not ssh_before_command
    ):
        gaps.append(
            "Missing Linux auth telemetry between SSH failures and command execution."
        )
    if "linux_auth_activity" in event_types and "suspicious_command_execution" not in event_types:
        gaps.append(
            "Missing suspicious command execution telemetry after observed auth activity."
        )
    if ssh_before_auth and not auth_before_command:
        gaps.append(
            "Auth activity was observed after SSH failures, but no follow-on command execution telemetry was correlated."
        )
    if not gaps:
        gaps.append(
            "No obvious telemetry gaps were identified for the correlated event set."
        )
    return gaps


@mcp.tool()
def correlate_security_events(events: list[dict]) -> str:
    """
    Correlate multiple security investigation findings into a possible attack chain.
    Uses simple deterministic rules only (no machine learning, API calls, SSH,
    external lookups, or threat intelligence feeds). Accepts normalized event dicts
    typically produced by earlier investigation tools.
    """
    if not isinstance(events, list):
        return json.dumps(
            {
                "status": "error",
                "analyst_note": "events must be a list of event dictionaries.",
            },
            indent=2,
        )

    if not events:
        escalation, next_steps = _correlation_escalation_and_steps("low")
        return json.dumps(
            {
                "status": "ok",
                "correlation_summary": "No events were provided for correlation.",
                "correlated_events": [],
                "attack_timeline": [],
                "possible_attack_chain": [],
                "mitre_mapping": [],
                "risk_level": "low",
                "confidence_score": 30,
                "escalation_recommendation": escalation,
                "detection_gaps": [
                    "Provide related SSH, auth, or command execution events to evaluate an attack chain."
                ],
                "recommended_next_steps": next_steps,
                "analyst_note": (
                    "This tool correlates multiple investigation findings using simple "
                    "deterministic rules. No events were supplied, so only baseline "
                    "guidance is returned."
                ),
            },
            indent=2,
        )

    normalized_events = [
        _normalize_correlation_event(event if isinstance(event, dict) else {})
        for event in events
    ]

    same_source_ip = _events_share_source_ip(normalized_events)
    same_host = _events_share_host(normalized_events)
    ssh_before_auth = _detect_event_sequence(
        normalized_events,
        "ssh_auth_failure",
        "linux_auth_activity",
    )
    auth_before_command = _detect_event_sequence(
        normalized_events,
        "linux_auth_activity",
        "suspicious_command_execution",
    )
    ssh_before_command = _detect_event_sequence(
        normalized_events,
        "ssh_auth_failure",
        "suspicious_command_execution",
    )
    medium_confidence_count = _count_medium_confidence_events(normalized_events)

    sequence_detected = ssh_before_auth or auth_before_command or ssh_before_command
    correlated_events = _collect_related_events(normalized_events, sequence_detected)
    if not correlated_events and (same_source_ip or same_host):
        correlated_events = normalized_events

    confidence_score, findings = _score_correlation(
        normalized_events,
        same_source_ip=same_source_ip,
        same_host=same_host,
        ssh_before_auth=ssh_before_auth,
        auth_before_command=auth_before_command,
        ssh_before_command=ssh_before_command,
        medium_confidence_count=medium_confidence_count,
    )

    risk_level = _risk_level_from_confidence(confidence_score)
    if len(correlated_events) >= 3:
        findings.append(
            "Rule 7: Three or more related events increase the overall risk level."
        )
        risk_level = _bump_risk_level(risk_level)

    timeline_source = correlated_events or normalized_events
    attack_timeline = _build_attack_timeline(timeline_source)
    event_types_in_order = [entry["event_type"] for entry in attack_timeline]
    if sequence_detected:
        possible_attack_chain = _build_possible_attack_chain(event_types_in_order)
    else:
        possible_attack_chain = []
    event_type_set = set(event_types_in_order)
    full_chain_detected = (
        "ssh_auth_failure" in event_type_set
        and "linux_auth_activity" in event_type_set
        and "suspicious_command_execution" in event_type_set
    )
    mitre_mapping = _build_correlation_mitre_mapping(
        event_types_in_order,
        chain_detected=full_chain_detected,
    )

    escalation_recommendation, recommended_next_steps = _correlation_escalation_and_steps(
        risk_level
    )
    detection_gaps = _build_correlation_detection_gaps(
        timeline_source,
        ssh_before_auth=ssh_before_auth,
        auth_before_command=auth_before_command,
        ssh_before_command=ssh_before_command,
    )

    if findings:
        correlation_summary = " ".join(findings)
    elif correlated_events:
        correlation_summary = (
            "Events share common observables but no stronger attack-chain sequence was detected."
        )
    else:
        correlation_summary = (
            "The supplied events appear unrelated based on shared IP, host, and sequence checks."
        )

    if possible_attack_chain:
        analyst_note = (
            "This tool applied beginner-friendly correlation rules to identify a possible "
            "attack chain across multiple investigation findings. Review the timeline, "
            "MITRE mapping, and recommended actions before escalation. No external lookups "
            "or automated response actions are performed."
        )
    elif correlated_events:
        analyst_note = (
            "Related observables were identified, but the event sequence does not yet "
            "form a complete attack chain. Continue gathering telemetry and re-run "
            "correlation as new findings arrive."
        )
    else:
        analyst_note = (
            "The supplied events do not appear strongly related. Continue monitoring and "
            "collect additional telemetry before treating this as a coordinated attack chain."
        )

    result = {
        "status": "ok",
        "correlation_summary": correlation_summary,
        "correlated_events": correlated_events,
        "attack_timeline": attack_timeline,
        "possible_attack_chain": possible_attack_chain,
        "mitre_mapping": mitre_mapping,
        "risk_level": risk_level,
        "confidence_score": confidence_score,
        "escalation_recommendation": escalation_recommendation,
        "detection_gaps": detection_gaps,
        "recommended_next_steps": recommended_next_steps,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_detection_recommendation(
    alert_type: str,
    severity: str,
    confidence_score: int,
    mitre_techniques: list[str] | None = None,
) -> str:
    """
    Recommend ways to improve future detection coverage after an investigated alert.
    Returns structured JSON with detection gaps, recommended detections, telemetry
    needs, MITRE coverage, and engineering notes. No API calls.

    Inputs come from a completed investigation (for example, investigate_ssh_alert
    or investigate_command_execution). confidence_score is accepted for workflow
    consistency but does not change the core recommendations.
    """
    if mitre_techniques is None:
        mitre_techniques = []

    severity_key = severity.lower()

    if alert_type == "ssh_auth_failure":
        detection_gaps = [
            "Missing brute-force correlation detection",
            "Missing success-after-failure detection",
        ]
        recommended_detections = [
            "Alert on >10 failed SSH logins in 10 minutes",
            "Alert on successful SSH login following repeated failures",
            "Alert on root login from uncommon source IP",
        ]
        telemetry_recommendations = [
            "SSH authentication logs",
            "PAM logs",
            "Process creation logs",
        ]
        mitre_coverage = [
            "T1110 Brute Force",
            "T1078 Valid Accounts",
        ]
        engineering_notes = [
            "Consider Sigma rule creation",
            "Consider Sentinel analytic rule",
            "Consider Wazuh correlation rule",
        ]
    elif alert_type == "suspicious_command_execution":
        detection_gaps = [
            "Missing download-and-execute detection",
            "Missing command-line monitoring",
        ]
        recommended_detections = [
            "curl immediately followed by bash",
            "wget followed by shell execution",
            "powershell encoded commands",
            "certutil downloads",
        ]
        telemetry_recommendations = [
            "Process creation logging",
            "Command-line auditing",
            "Network connection logging",
        ]
        mitre_coverage = [
            "T1105 Ingress Tool Transfer",
            "T1059 Command and Scripting Interpreter",
            "T1027 Obfuscated Files or Information",
        ]
        engineering_notes = [
            "Create Sigma detections",
            "Create Sentinel analytics",
            "Create Defender custom detections",
        ]
    else:
        detection_gaps = [
            "Missing baseline behavioral detection",
            "Missing cross-source correlation",
        ]
        recommended_detections = [
            "Alert on rare or first-seen event patterns",
            "Alert on anomalous sequences involving the same host or user",
        ]
        telemetry_recommendations = [
            "Authentication logs",
            "Process creation logging",
            "Network connection logging",
        ]
        if mitre_techniques:
            mitre_coverage = list(mitre_techniques)
        else:
            mitre_coverage = [
                "Review MITRE ATT&CK mapping for this alert family",
            ]
        engineering_notes = [
            "Document alert type and observables before building rules",
            "Review existing SIEM rules for overlap",
            "Consider Sigma or vendor-native rule formats",
        ]

    if mitre_techniques and alert_type in (
        "ssh_auth_failure",
        "suspicious_command_execution",
    ):
        engineering_notes.append(
            "Investigation mapped techniques: " + ", ".join(mitre_techniques)
        )

    if severity_key == "high":
        engineering_notes.append("Prioritize engineering work")
        engineering_notes.append("Validate existing detections immediately")

    result = {
        "status": "ok",
        "detection_gaps": detection_gaps,
        "recommended_detections": recommended_detections,
        "telemetry_recommendations": telemetry_recommendations,
        "mitre_coverage": mitre_coverage,
        "engineering_notes": engineering_notes,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_sigma_rule(
    alert_type: str,
    title: str = "",
    severity: str = "medium",
    mitre_techniques: list[str] | None = None,
) -> str:
    """
    Generate a beginner-friendly Sigma detection rule draft from a supported
    alert type. Returns JSON with a YAML rule string (no API calls).
    """
    if mitre_techniques is None:
        mitre_techniques = []

    level = _sigma_level_from_severity(severity)
    tags_block = _format_sigma_tags(mitre_techniques)
    tags_suffix = f"\n{tags_block}" if tags_block else ""

    if alert_type == "ssh_auth_failure":
        rule_title = title or "Repeated SSH Failed Logins"
        sigma_rule = f"""title: {rule_title}
status: experimental
description: Detects repeated SSH authentication failures in Linux sshd logs.
logsource:
    product: linux
    service: sshd
detection:
    keywords:
        - 'Failed password'
        - 'sshd'
    condition: keywords
falsepositives:
    - Mistyped admin password
    - Misconfigured automation
level: {level}{tags_suffix}"""

        analyst_note = (
            "This tool returns a Sigma rule draft with status experimental. "
            "Keyword matching on 'Failed password' and 'sshd' is a starting point; "
            "you will likely need correlation or threshold logic (for example, "
            "multiple failures in a time window) before production use. "
            "Test in your environment, tune false positives, and convert to "
            "Wazuh, Sentinel, or other vendor formats manually. "
            "No rules are deployed automatically from this MCP server."
        )

    elif alert_type == "suspicious_command_execution":
        rule_title = title or "Suspicious Download and Execute Command"
        sigma_rule = f"""title: {rule_title}
status: experimental
description: Detects suspicious download-and-execute command patterns on Linux hosts.
logsource:
    product: linux
detection:
    keywords:
        - 'curl'
        - 'wget'
        - '| bash'
        - 'bash -c'
    condition: keywords
falsepositives:
    - Legitimate admin scripts
    - Software installation scripts
level: {level}{tags_suffix}"""

        analyst_note = (
            "This tool returns a Sigma rule draft with status experimental. "
            "Command-line indicators (curl, wget, piped bash) require process "
            "or audit telemetry on Linux hosts. Validate that your log source "
            "captures command lines before enabling this rule. "
            "Test in your environment, tune false positives, and convert to "
            "Wazuh, Sentinel, or other vendor formats manually. "
            "No rules are deployed automatically from this MCP server."
        )

    else:
        result = {
            "status": "error",
            "sigma_rule": "",
            "analyst_note": (
                f"Unsupported alert_type '{alert_type}'. "
                "Supported: ssh_auth_failure, suspicious_command_execution."
            ),
        }
        return json.dumps(result, indent=2)

    result = {
        "status": "ok",
        "sigma_rule": sigma_rule,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_sentinel_analytic_rule(
    alert_type: str,
    severity: str,
    mitre_techniques: list[str] | None = None,
) -> str:
    """
    Generate a beginner-friendly Microsoft Sentinel scheduled analytic rule draft
    from a supported alert type. Returns JSON with rule metadata and KQL
    (no API calls, no automatic deployment).
    """
    if mitre_techniques is None:
        mitre_techniques = []

    severity_key = severity.lower()
    mitre_mapping = _build_mitre_mapping(alert_type, mitre_techniques)

    if alert_type == "ssh_auth_failure":
        rule_name = "Repeated SSH Failed Logins"
        description = (
            "Detects brute-force SSH activity via repeated failed password "
            "attempts in syslog."
        )
        kql = """// Threshold: 10 failed logins in 10 minutes from the same source IP
let FailureThreshold = 10;
let TimeWindow = 10m;
Syslog
| where TimeGenerated >= ago(1d)
| where SyslogMessage has "Failed password"
| where SyslogMessage has "sshd"
| extend SourceIP = extract(@"from ([0-9.]+) port", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize FailedLoginCount = count() by SourceIP, bin(TimeGenerated, TimeWindow)
| where FailedLoginCount >= FailureThreshold"""
        analyst_note = (
            "This tool returns a Sentinel scheduled analytic rule draft. "
            "Paste the KQL into Azure Sentinel → Analytics → Scheduled query rule. "
            "The query correlates failed SSH logins by source IP over 10-minute bins; "
            "tune FailureThreshold and TimeWindow for your environment. "
            "Requires Syslog ingestion with sshd auth messages. "
            "Review false positives from mistyped passwords or automation. "
            "No rules are deployed automatically from this MCP server."
        )

    elif alert_type == "suspicious_command_execution":
        rule_name = "Suspicious Download and Execute Command"
        description = (
            "Detects curl, wget, bash -c, and encoded PowerShell in "
            "process and syslog telemetry."
        )
        kql = """union
    (Syslog
    | where TimeGenerated >= ago(1d)
    | where SyslogMessage has_any ("curl", "wget", "bash -c")
    | project TimeGenerated, Computer, CommandLine = SyslogMessage, DataSource = "Syslog"),
    (DeviceProcessEvents
    | where TimeGenerated >= ago(1d)
    | where ProcessCommandLine has_any ("curl", "wget", "bash -c")
        or (ProcessCommandLine has "powershell"
            and (ProcessCommandLine has "-enc" or ProcessCommandLine has "-EncodedCommand"))
    | project TimeGenerated, Computer = DeviceName, CommandLine = ProcessCommandLine, DataSource = "DeviceProcessEvents")"""
        analyst_note = (
            "This tool returns a Sentinel scheduled analytic rule draft. "
            "Paste the KQL into Azure Sentinel → Analytics → Scheduled query rule. "
            "The query unions Linux Syslog and Microsoft Defender DeviceProcessEvents "
            "to catch curl, wget, bash -c, and encoded PowerShell patterns. "
            "Validate that your tenant ingests both tables before enabling. "
            "Tune indicators to reduce false positives from admin scripts. "
            "No rules are deployed automatically from this MCP server."
        )

    else:
        result = {
            "rule_name": "",
            "description": "",
            "severity": "",
            "mitre_mapping": [],
            "kql": "",
            "analyst_note": (
                f"Unsupported alert_type '{alert_type}'. "
                "Supported: ssh_auth_failure, suspicious_command_execution."
            ),
        }
        return json.dumps(result, indent=2)

    result = {
        "rule_name": rule_name,
        "description": description,
        "severity": severity_key,
        "mitre_mapping": mitre_mapping,
        "kql": kql,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_qradar_aql_detection(
    alert_type: str,
    severity: str,
    mitre_techniques: list[str] | None = None,
) -> str:
    """
    Generate a beginner-friendly IBM QRadar AQL detection rule draft from a
    supported alert type. Returns JSON with rule metadata and AQL
    (no API calls, no automatic deployment).

    Supported alert types:
    - ssh_auth_failure: repeated failed SSH logins
    - suspicious_command_execution: curl, wget, bash -c, encoded PowerShell
    """
    if mitre_techniques is None:
        mitre_techniques = []

    severity_key = severity.lower()
    mitre_mapping = _build_mitre_mapping(alert_type, mitre_techniques)

    if alert_type == "ssh_auth_failure":
        rule_name = "Repeated SSH Failed Logins"
        description = (
            "Detects brute-force SSH activity via repeated failed password "
            "attempts in syslog."
        )
        aql = """SELECT
  sourceIP AS SourceIP,
  COUNT(*) AS FailedLoginCount
FROM events
WHERE
  UTF8(payload) ILIKE '%Failed password%'
  AND UTF8(payload) ILIKE '%sshd%'
  AND sourceIP IS NOT NULL
LAST 10 MINUTES
GROUP BY sourceIP
HAVING COUNT(*) >= 10"""
        analyst_note = (
            "This tool returns a QRadar AQL detection rule draft. "
            "Paste the AQL into QRadar → Log Activity → New Search, or use it "
            "as the basis for a Custom Rule. "
            "The query correlates failed SSH logins by source IP over 10 minutes; "
            "tune the HAVING threshold and LAST window for your environment. "
            "Requires syslog ingestion with sshd auth messages. "
            "Review false positives from mistyped passwords or automation. "
            "No rules are deployed automatically from this MCP server."
        )

    elif alert_type == "suspicious_command_execution":
        rule_name = "Suspicious Download and Execute Command"
        description = (
            "Detects curl, wget, bash -c, and encoded PowerShell in "
            "event payloads."
        )
        aql = """SELECT
  DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
  sourceIP AS SourceIP,
  username AS Username,
  UTF8(payload) AS CommandLine
FROM events
WHERE
  (
    UTF8(payload) ILIKE '%curl%'
    OR UTF8(payload) ILIKE '%wget%'
    OR UTF8(payload) ILIKE '%bash -c%'
    OR (
      UTF8(payload) ILIKE '%powershell%'
      AND (
        UTF8(payload) ILIKE '%-enc%'
        OR UTF8(payload) ILIKE '%-EncodedCommand%'
      )
    )
  )
LAST 1 DAYS"""
        analyst_note = (
            "This tool returns a QRadar AQL detection rule draft. "
            "Paste the AQL into QRadar → Log Activity → New Search, or use it "
            "as the basis for a Custom Rule. "
            "The query matches curl, wget, bash -c, and encoded PowerShell "
            "patterns in event payloads. "
            "Validate that your log sources ingest command or process data. "
            "Tune indicators to reduce false positives from admin scripts. "
            "No rules are deployed automatically from this MCP server."
        )

    else:
        result = {
            "rule_name": "",
            "description": "",
            "severity": "",
            "mitre_mapping": [],
            "aql": "",
            "analyst_note": (
                f"Unsupported alert_type '{alert_type}'. "
                "Supported: ssh_auth_failure, suspicious_command_execution."
            ),
        }
        return json.dumps(result, indent=2)

    result = {
        "rule_name": rule_name,
        "description": description,
        "severity": severity_key,
        "mitre_mapping": mitre_mapping,
        "aql": aql,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_detection_package(
    alert_type: str,
    severity: str,
    confidence_score: int,
    mitre_techniques: list[str] | None = None,
) -> str:
    """
    Bundle detection engineering outputs into a single package after investigation.
    Reuses generate_detection_recommendation, generate_sigma_rule,
    generate_sentinel_analytic_rule, and generate_qradar_aql_detection.
    No API calls and no automatic rule deployment.

    Inputs typically come from investigate_ssh_alert or investigate_command_execution:
    alert_type, severity, confidence_score, and optional mitre_techniques.

    Sigma, Sentinel, and QRadar rule drafts support ssh_auth_failure and
    suspicious_command_execution. Other alert types still receive generic
    detection recommendations.

    Returns JSON with:
    - detection_recommendations: gaps, detections, telemetry, MITRE, engineering notes
    - sigma_rule: YAML draft and analyst note (or error for unsupported alert types)
    - sentinel_analytic_rule: Sentinel KQL draft with MITRE mapping and analyst note
    - qradar_aql_detection: QRadar AQL draft with MITRE mapping and analyst note
    - engineering_summary: beginner-friendly rollup for analysts
    """
    if mitre_techniques is None:
        mitre_techniques = []

    detection_recommendations = json.loads(
        generate_detection_recommendation(
            alert_type=alert_type,
            severity=severity,
            confidence_score=confidence_score,
            mitre_techniques=mitre_techniques,
        )
    )

    sigma_rule = json.loads(
        generate_sigma_rule(
            alert_type=alert_type,
            severity=severity,
            mitre_techniques=mitre_techniques,
        )
    )

    sentinel_rule = json.loads(
        generate_sentinel_analytic_rule(
            alert_type=alert_type,
            severity=severity,
            mitre_techniques=mitre_techniques,
        )
    )

    qradar_rule = json.loads(
        generate_qradar_aql_detection(
            alert_type=alert_type,
            severity=severity,
            mitre_techniques=mitre_techniques,
        )
    )

    engineering_summary = _build_engineering_summary(
        alert_type=alert_type,
        severity=severity,
        confidence_score=confidence_score,
        mitre_techniques=mitre_techniques,
        detection_recommendations=detection_recommendations,
        sigma_rule=sigma_rule,
        sentinel_rule=sentinel_rule,
        qradar_rule=qradar_rule,
    )

    result = {
        "detection_recommendations": detection_recommendations,
        "sigma_rule": sigma_rule,
        "sentinel_analytic_rule": sentinel_rule,
        "qradar_aql_detection": qradar_rule,
        "engineering_summary": engineering_summary,
    }

    return json.dumps(result, indent=2)


def _build_command_incident_ticket_note(investigation: dict) -> dict:
    """Structured analyst documentation for command execution incidents."""
    return {
        "summary": investigation.get("command_summary", ""),
        "severity": investigation.get("severity", "unknown"),
        "confidence_score": investigation.get("confidence_score", 0),
        "priority": investigation.get("priority", "unknown"),
        "suspicious_indicators": investigation.get("suspicious_indicators", []),
        "mitre_mapping": investigation.get("mitre_mapping", []),
        "recommended_actions": investigation.get("recommended_actions", []),
        "documentation_guidance": (
            "Paste this summary into ServiceNow, Jira, or IBM SOAR. "
            "Add timestamps, ticket IDs, and the full command line from the "
            "original alert before submission."
        ),
    }


def _correlation_event_types(correlation: dict) -> set[str]:
    """Collect event types present in a correlation result."""
    event_types: set[str] = set()
    for event in correlation.get("correlated_events", []):
        event_type = event.get("event_type", "")
        if event_type:
            event_types.add(event_type)
    for entry in correlation.get("attack_timeline", []):
        event_type = entry.get("event_type", "")
        if event_type:
            event_types.add(event_type)
    return event_types


def _runbook_types_for_correlation(correlation: dict) -> list[str]:
    """Return runbook alert types relevant to correlated events."""
    event_types = _correlation_event_types(correlation)
    runbook_types: list[str] = []
    for alert_type in (
        "ssh_auth_failure",
        "linux_auth_activity",
        "suspicious_command_execution",
    ):
        if alert_type in event_types:
            runbook_types.append(alert_type)
    return runbook_types


def _investigate_wazuh_alert_incident(
    file_path: str,
    failures_last_10_minutes: int,
    success_after_failure: bool,
    source_is_known_admin_host: bool,
) -> str:
    workflow_used = ["identify_alert_type"]
    if not file_path or not file_path.strip():
        return json.dumps(
            {
                "status": "error",
                "analyst_note": "file_path is required for input_type wazuh_alert.",
            },
            indent=2,
        )

    classification_raw = identify_alert_type(file_path)
    if classification_raw.startswith("Error:"):
        return json.dumps(
            {
                "status": "error",
                "input_type": "wazuh_alert",
                "workflow_used": workflow_used,
                "analyst_note": classification_raw,
            },
            indent=2,
        )

    classification = json.loads(classification_raw)
    alert_type = classification.get("alert_type", "unknown")

    if alert_type == "ssh_auth_failure":
        workflow_used.extend(
            [
                "investigate_ssh_alert",
                "generate_detection_package",
                "generate_soc_ticket_note",
            ]
        )
        investigation_raw = investigate_ssh_alert(
            file_path=file_path,
            failures_last_10_minutes=failures_last_10_minutes,
            success_after_failure=success_after_failure,
            source_is_known_admin_host=source_is_known_admin_host,
        )
        if investigation_raw.startswith("Error:"):
            return json.dumps(
                {
                    "status": "error",
                    "input_type": "wazuh_alert",
                    "workflow_used": workflow_used,
                    "alert_classification": classification,
                    "analyst_note": investigation_raw,
                },
                indent=2,
            )

        investigation = json.loads(investigation_raw)
        obs = investigation["alert_summary"]["observables"]
        scored = investigation["risk_score"]
        next_action = investigation["next_action"]

        detection_package = json.loads(
            generate_detection_package(
                alert_type="ssh_auth_failure",
                severity=scored["severity"],
                confidence_score=scored["confidence_score"],
            )
        )

        ticket_raw = generate_soc_ticket_note(
            source_ip=obs["source_ip"],
            target_user=obs["target_user"],
            host=obs["host"],
            severity=scored["severity"],
            confidence_score=scored["confidence_score"],
            priority=scored["priority"],
            rule_id=str(obs["rule_id"]),
            rule_description=obs["rule_description"],
            recommended_action=next_action["recommended_action"],
        )
        ticket = json.loads(ticket_raw)

        incident_summary = investigation["investigation_summary"].get(
            "executive_summary",
            investigation["alert_summary"].get("summary", ""),
        )
        recommended_next_steps = investigation["investigation_summary"].get(
            "recommended_actions", []
        )

        result = {
            "status": "ok",
            "input_type": "wazuh_alert",
            "workflow_used": workflow_used,
            "incident_summary": incident_summary,
            "alert_classification": classification,
            "investigation_results": investigation,
            "correlation_results": None,
            "runbook": investigation.get("investigation_runbook"),
            "detection_package": detection_package,
            "ticket_note": ticket.get("ticket_note"),
            "recommended_next_steps": recommended_next_steps,
            "analyst_note": (
                "End-to-end SSH authentication failure investigation completed using "
                "identify_alert_type, investigate_ssh_alert, generate_detection_package, "
                "and generate_soc_ticket_note. Review ticket note and detection package "
                "before escalation."
            ),
        }
        return json.dumps(result, indent=2)

    if alert_type == "suspicious_command_execution":
        workflow_used.append("manual_routing_guidance")
        result = {
            "status": "ok",
            "input_type": "wazuh_alert",
            "workflow_used": workflow_used,
            "incident_summary": (
                "Wazuh alert classified as suspicious command execution. "
                "File-based command execution routing is identified but not yet "
                "chained in this workflow."
            ),
            "alert_classification": classification,
            "investigation_results": None,
            "correlation_results": None,
            "runbook": None,
            "detection_package": None,
            "ticket_note": None,
            "recommended_next_steps": [
                "Re-run investigate_security_incident with input_type='command_execution'.",
                "Provide the command string and host/user context from the alert file.",
            ],
            "analyst_note": (
                "Alert type suspicious_command_execution was identified from the Wazuh file, "
                "but the full command execution chain requires input_type='command_execution' "
                "with the command details for now."
            ),
        }
        return json.dumps(result, indent=2)

    workflow_used.append("manual_review")
    result = {
        "status": "ok",
        "input_type": "wazuh_alert",
        "workflow_used": workflow_used,
        "incident_summary": (
            "Wazuh alert could not be automatically classified. Manual analyst review is required."
        ),
        "alert_classification": classification,
        "investigation_results": None,
        "correlation_results": None,
        "runbook": json.loads(
            generate_investigation_runbook(
                alert_type="unknown",
                severity="medium",
                confidence_score=40,
            )
        ),
        "detection_package": None,
        "ticket_note": None,
        "recommended_next_steps": [
            "Review detected_fields from alert_classification.",
            "Determine whether the alert is SSH, command execution, or another category.",
            "Run the appropriate single-purpose investigation tool once classified.",
        ],
        "analyst_note": classification.get(
            "reasoning",
            "Unknown alert type — manual review incident package returned.",
        ),
    }
    return json.dumps(result, indent=2)


def _investigate_command_execution_incident(
    command: str,
    hostname: str,
    username: str,
    source_ip: str,
) -> str:
    workflow_used = [
        "investigate_command_execution",
        "generate_investigation_runbook",
        "generate_detection_package",
    ]

    if not command or not command.strip():
        return json.dumps(
            {
                "status": "error",
                "analyst_note": "command is required for input_type command_execution.",
            },
            indent=2,
        )

    investigation_raw = investigate_command_execution(
        command=command,
        hostname=hostname,
        username=username,
        source_ip=source_ip,
    )
    investigation = json.loads(investigation_raw)
    if investigation.get("status") == "error":
        return json.dumps(
            {
                "status": "error",
                "input_type": "command_execution",
                "workflow_used": workflow_used,
                "analyst_note": investigation.get(
                    "analyst_notes",
                    "command execution investigation failed.",
                ),
            },
            indent=2,
        )

    severity = investigation["severity"]
    confidence_score = investigation["confidence_score"]
    mitre_techniques = [
        entry["technique_id"] for entry in investigation.get("mitre_mapping", [])
    ]

    runbook = json.loads(
        generate_investigation_runbook(
            alert_type="suspicious_command_execution",
            severity=severity,
            confidence_score=confidence_score,
        )
    )

    detection_package = json.loads(
        generate_detection_package(
            alert_type="suspicious_command_execution",
            severity=severity,
            confidence_score=confidence_score,
            mitre_techniques=mitre_techniques,
        )
    )

    ticket_note = _build_command_incident_ticket_note(investigation)

    result = {
        "status": "ok",
        "input_type": "command_execution",
        "workflow_used": workflow_used,
        "incident_summary": investigation.get("command_summary", ""),
        "alert_classification": {
            "alert_type": "suspicious_command_execution",
            "recommended_workflow": "investigate_command_execution",
        },
        "investigation_results": investigation,
        "correlation_results": None,
        "runbook": runbook,
        "detection_package": detection_package,
        "ticket_note": ticket_note,
        "recommended_next_steps": investigation.get("recommended_actions", []),
        "analyst_note": investigation.get("analyst_notes", ""),
    }
    return json.dumps(result, indent=2)


def _investigate_event_collection_incident(events: list[dict] | None) -> str:
    workflow_used = ["correlate_security_events"]

    if not events:
        return json.dumps(
            {
                "status": "error",
                "analyst_note": "events is required and cannot be empty for input_type event_collection.",
            },
            indent=2,
        )

    correlation = json.loads(correlate_security_events(events))
    if correlation.get("status") == "error":
        return json.dumps(
            {
                "status": "error",
                "input_type": "event_collection",
                "workflow_used": workflow_used,
                "analyst_note": correlation.get(
                    "analyst_note",
                    "event correlation failed.",
                ),
            },
            indent=2,
        )

    runbook_types = _runbook_types_for_correlation(correlation)
    if runbook_types:
        workflow_used.append("generate_investigation_runbook")

    risk_level = correlation.get("risk_level", "medium")
    confidence_score = correlation.get("confidence_score", 60)
    severity = risk_level if risk_level in ("low", "medium", "high") else "medium"

    runbooks: dict | None = None
    if runbook_types:
        runbooks = {}
        for alert_type in runbook_types:
            runbooks[alert_type] = json.loads(
                generate_investigation_runbook(
                    alert_type=alert_type,
                    severity=severity,
                    confidence_score=confidence_score,
                )
            )

    incident_summary = correlation.get("correlation_summary", "")
    if correlation.get("possible_attack_chain"):
        chain_text = " → ".join(correlation["possible_attack_chain"])
        incident_summary = f"{incident_summary} Possible attack chain: {chain_text}."

    result = {
        "status": "ok",
        "input_type": "event_collection",
        "workflow_used": workflow_used,
        "incident_summary": incident_summary,
        "alert_classification": None,
        "investigation_results": None,
        "correlation_results": correlation,
        "runbook": runbooks,
        "detection_package": None,
        "ticket_note": None,
        "recommended_next_steps": correlation.get("recommended_next_steps", []),
        "analyst_note": correlation.get("analyst_note", ""),
    }
    return json.dumps(result, indent=2)


@mcp.tool()
def investigate_security_incident(
    input_type: str,
    file_path: str = "",
    command: str = "",
    hostname: str = "unknown",
    username: str = "unknown",
    source_ip: str = "unknown",
    events: list[dict] | None = None,
    failures_last_10_minutes: int = 1,
    success_after_failure: bool = False,
    source_is_known_admin_host: bool = False,
) -> str:
    """
    Run an end-to-end Security Copilot-style investigation chain by orchestrating
    existing MCP tools. Supports Wazuh alert files, suspicious command execution
    inputs, or collections of normalized security events. No API calls, SSH, or
    external lookups.

    input_type values:
    - wazuh_alert: identify alert type, investigate SSH alerts, build detection
      package and ticket note
    - command_execution: investigate command, generate runbook and detection package
    - event_collection: correlate events and recommend runbooks for attack chains
    """
    supported_types = {"wazuh_alert", "command_execution", "event_collection"}
    if input_type not in supported_types:
        return json.dumps(
            {
                "status": "error",
                "analyst_note": (
                    "supported input types are wazuh_alert, command_execution, "
                    "event_collection"
                ),
            },
            indent=2,
        )

    if input_type == "wazuh_alert":
        return _investigate_wazuh_alert_incident(
            file_path=file_path,
            failures_last_10_minutes=failures_last_10_minutes,
            success_after_failure=success_after_failure,
            source_is_known_admin_host=source_is_known_admin_host,
        )

    if input_type == "command_execution":
        return _investigate_command_execution_incident(
            command=command,
            hostname=hostname,
            username=username,
            source_ip=source_ip,
        )

    return _investigate_event_collection_incident(events)


# --- Incident report generation (format-only, no API/SSH/file I/O) ---

_SUPPORTED_REPORT_TYPES = {"soc", "executive", "technical"}


def _coerce_list(value) -> list:
    """Return a list from mixed input types; empty list when missing."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def _first_non_empty_str(*values: str) -> str:
    """Return the first non-empty string from candidates."""
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _extract_incident_fields(incident_data: dict) -> dict:
    """Normalize investigation or correlation output into report-friendly fields."""
    investigation = incident_data.get("investigation_results") or {}
    if not isinstance(investigation, dict):
        investigation = {}

    correlation = incident_data.get("correlation_results")
    if not isinstance(correlation, dict):
        if isinstance(incident_data.get("correlated_events"), list):
            correlation = incident_data
        else:
            correlation = {}

    risk_score = investigation.get("risk_score") or {}
    if not isinstance(risk_score, dict):
        risk_score = {}

    investigation_summary = investigation.get("investigation_summary") or {}
    if not isinstance(investigation_summary, dict):
        investigation_summary = {}

    alert_summary = investigation.get("alert_summary") or {}
    if not isinstance(alert_summary, dict):
        alert_summary = {}

    alert_observables = alert_summary.get("observables") or {}
    if not isinstance(alert_observables, dict):
        alert_observables = {}

    summary_observables = investigation_summary.get("observables") or {}
    if not isinstance(summary_observables, dict):
        summary_observables = {}

    detection_recommendations = investigation.get("detection_recommendations") or {}
    if not isinstance(detection_recommendations, dict):
        detection_recommendations = {}

    detection_package = incident_data.get("detection_package") or {}
    if not isinstance(detection_package, dict):
        detection_package = {}

    runbook = incident_data.get("runbook")
    if runbook is not None and not isinstance(runbook, (dict, str)):
        runbook = None

    incident_summary = _first_non_empty_str(
        incident_data.get("incident_summary", ""),
        correlation.get("correlation_summary", ""),
        investigation.get("command_summary", ""),
        investigation_summary.get("executive_summary", ""),
    )

    risk_level = _first_non_empty_str(
        correlation.get("risk_level", ""),
        investigation.get("severity", ""),
        risk_score.get("severity", ""),
    ) or "unknown"

    confidence_score = (
        correlation.get("confidence_score")
        if correlation.get("confidence_score") is not None
        else investigation.get("confidence_score")
        if investigation.get("confidence_score") is not None
        else risk_score.get("confidence_score")
    )
    if confidence_score is None:
        confidence_score = 0

    recommended_next_steps = _coerce_list(incident_data.get("recommended_next_steps"))
    if not recommended_next_steps:
        recommended_next_steps = _coerce_list(correlation.get("recommended_next_steps"))
    if not recommended_next_steps:
        recommended_next_steps = _coerce_list(investigation.get("recommended_actions"))
    if not recommended_next_steps:
        recommended_next_steps = _coerce_list(risk_score.get("recommended_next_steps"))

    mitre_mapping = _coerce_list(correlation.get("mitre_mapping"))
    if not mitre_mapping:
        mitre_mapping = _coerce_list(investigation.get("mitre_mapping"))

    detection_gaps = _coerce_list(correlation.get("detection_gaps"))
    if not detection_gaps:
        detection_gaps = _coerce_list(detection_recommendations.get("detection_gaps"))

    detection_opportunities: list = []
    engineering_summary = detection_package.get("engineering_summary")
    if isinstance(engineering_summary, str) and engineering_summary.strip():
        detection_opportunities.append(engineering_summary.strip())
    detection_opportunities.extend(
        _coerce_list(detection_recommendations.get("recommended_detections"))
    )
    if isinstance(runbook, dict):
        if "detection_engineering_opportunities" in runbook:
            detection_opportunities.extend(
                _coerce_list(runbook.get("detection_engineering_opportunities"))
            )
        else:
            for entry in runbook.values():
                if isinstance(entry, dict):
                    detection_opportunities.extend(
                        _coerce_list(entry.get("detection_engineering_opportunities"))
                    )

    observables_dict = summary_observables or alert_observables
    if not observables_dict and correlation.get("correlated_events"):
        first_event = correlation["correlated_events"][0]
        if isinstance(first_event, dict):
            observables_dict = {
                key: first_event.get(key, "")
                for key in ("source_ip", "host", "username", "event_type", "description")
                if first_event.get(key)
            }

    return {
        "incident_summary": incident_summary,
        "risk_level": risk_level,
        "confidence_score": int(confidence_score),
        "recommended_next_steps": recommended_next_steps,
        "correlation_results": correlation,
        "correlation_summary": correlation.get("correlation_summary", ""),
        "attack_timeline": _coerce_list(correlation.get("attack_timeline")),
        "possible_attack_chain": _coerce_list(correlation.get("possible_attack_chain")),
        "mitre_mapping": mitre_mapping,
        "observables_dict": observables_dict if isinstance(observables_dict, dict) else {},
        "detection_gaps": detection_gaps,
        "detection_opportunities": detection_opportunities,
        "runbook": runbook,
        "ticket_note": incident_data.get("ticket_note"),
        "workflow_used": _coerce_list(incident_data.get("workflow_used")),
        "input_type": incident_data.get("input_type", ""),
        "escalation_recommendation": correlation.get("escalation_recommendation", ""),
    }


def _extract_affected_assets(extracted: dict) -> list[dict]:
    """Collect hosts, users, and source IPs from timeline and correlated events."""
    assets: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add_asset(asset_type: str, value: str) -> None:
        cleaned = (value or "").strip()
        if not cleaned or cleaned == "unknown":
            return
        key = (asset_type, cleaned)
        if key in seen:
            return
        seen.add(key)
        assets.append({"type": asset_type, "value": cleaned})

    for step in extracted.get("attack_timeline", []):
        if not isinstance(step, dict):
            continue
        add_asset("host", step.get("host", ""))
        add_asset("username", step.get("username", ""))
        add_asset("source_ip", step.get("source_ip", ""))

    correlation = extracted.get("correlation_results") or {}
    for event in _coerce_list(correlation.get("correlated_events")):
        if not isinstance(event, dict):
            continue
        add_asset("host", event.get("host", ""))
        add_asset("username", event.get("username", ""))
        add_asset("source_ip", event.get("source_ip", ""))

    for key, label in (
        ("host", "host"),
        ("target_user", "username"),
        ("username", "username"),
        ("source_ip", "source_ip"),
    ):
        add_asset(label, extracted.get("observables_dict", {}).get(key, ""))

    return assets


def _extract_observables_list(extracted: dict) -> list[dict]:
    """Flatten observables into a list of type/value pairs."""
    observables: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add_observable(obs_type: str, value: str) -> None:
        cleaned = (value or "").strip()
        if not cleaned or cleaned == "unknown":
            return
        key = (obs_type, cleaned)
        if key in seen:
            return
        seen.add(key)
        observables.append({"type": obs_type, "value": cleaned})

    for key, obs_type in (
        ("source_ip", "source_ip"),
        ("target_user", "username"),
        ("username", "username"),
        ("host", "host"),
        ("rule_id", "rule_id"),
        ("rule_description", "rule_description"),
        ("event_type", "event_type"),
        ("description", "description"),
    ):
        add_observable(obs_type, extracted.get("observables_dict", {}).get(key, ""))

    for step in extracted.get("attack_timeline", []):
        if not isinstance(step, dict):
            continue
        add_observable("event_type", step.get("event_type", ""))
        add_observable("source_ip", step.get("source_ip", ""))
        add_observable("host", step.get("host", ""))
        add_observable("username", step.get("username", ""))

    return observables


def _risk_assessment_dict(extracted: dict, escalation_needed: bool) -> dict:
    """Build a shared risk assessment block for all report types."""
    risk_level = extracted.get("risk_level", "unknown")
    confidence_score = extracted.get("confidence_score", 0)
    summary_parts = [
        f"Risk level: {risk_level}.",
        f"Confidence score: {confidence_score}/100.",
    ]
    if extracted.get("possible_attack_chain"):
        chain_text = " → ".join(extracted["possible_attack_chain"])
        summary_parts.append(f"Possible attack chain: {chain_text}.")
    elif extracted.get("incident_summary"):
        summary_parts.append(extracted["incident_summary"])
    else:
        summary_parts.append("Limited incident context was available for assessment.")

    escalation_text = extracted.get("escalation_recommendation", "")
    if escalation_text:
        summary_parts.append(escalation_text)

    return {
        "risk_level": risk_level,
        "confidence_score": confidence_score,
        "escalation_needed": escalation_needed,
        "summary": " ".join(summary_parts),
    }


def _default_lessons_learned(extracted: dict) -> list[str]:
    """Return baseline lessons learned when no attack chain is present."""
    if extracted.get("possible_attack_chain"):
        return [
            (
                "Correlate authentication failures, successful logins, and command "
                "execution from the same source to detect multi-stage intrusions earlier."
            ),
            (
                "Document the attack chain stages and MITRE mappings in the ticket "
                "to improve future detection engineering."
            ),
        ]
    return [
        "Maintain consistent event normalization so correlation rules can link related activity.",
        "Review detection coverage for the observed alert types after closure.",
    ]


def _report_title(report_type: str, extracted: dict) -> str:
    """Generate a short title for the incident report."""
    risk_level = extracted.get("risk_level", "unknown").upper()
    if report_type == "executive":
        return f"Executive Security Incident Brief — {risk_level} Risk"
    if report_type == "technical":
        return f"Technical Incident Report — {risk_level} Severity"
    return f"SOC Incident Report — {risk_level} Severity"


def _build_soc_report_sections(extracted: dict) -> dict:
    """Build balanced SOC analyst report content."""
    risk_level = extracted.get("risk_level", "unknown")
    confidence_score = extracted.get("confidence_score", 0)
    escalation_needed = risk_level == "high" or confidence_score >= 70

    executive_parts = []
    if extracted.get("incident_summary"):
        executive_parts.append(extracted["incident_summary"])
    else:
        executive_parts.append(
            "A security incident was reviewed using available investigation outputs."
        )
    executive_parts.append(
        f"The case is assessed at {risk_level} risk with confidence {confidence_score}/100."
    )
    if escalation_needed:
        executive_parts.append(
            "Escalation to senior analysts or incident response is recommended."
        )
    else:
        executive_parts.append(
            "Continue structured investigation and monitoring before escalation."
        )

    technical_parts = []
    if extracted.get("possible_attack_chain"):
        chain_text = " → ".join(extracted["possible_attack_chain"])
        technical_parts.append(f"Observed attack chain stages: {chain_text}.")
    if extracted.get("attack_timeline"):
        technical_parts.append(
            f"Timeline contains {len(extracted['attack_timeline'])} ordered event(s)."
        )
    observables = _extract_observables_list(extracted)
    if observables:
        observable_text = ", ".join(
            f"{item['type']}={item['value']}" for item in observables[:6]
        )
        technical_parts.append(f"Key observables: {observable_text}.")
    if not technical_parts:
        technical_parts.append(
            "No detailed timeline or observables were supplied in the incident data."
        )

    detection_opportunities = list(extracted.get("detection_gaps", []))
    detection_opportunities.extend(extracted.get("detection_opportunities", []))

    return {
        "report_title": _report_title("soc", extracted),
        "executive_summary": " ".join(executive_parts),
        "technical_summary": " ".join(technical_parts),
        "incident_timeline": extracted.get("attack_timeline", []),
        "affected_assets": _extract_affected_assets(extracted),
        "observables": observables,
        "mitre_mapping": extracted.get("mitre_mapping", []),
        "risk_assessment": _risk_assessment_dict(extracted, escalation_needed),
        "containment_recommendations": extracted.get("recommended_next_steps", [])[:8],
        "detection_opportunities": detection_opportunities[:8],
        "lessons_learned": _default_lessons_learned(extracted),
        "analyst_notes": (
            "SOC incident report generated from supplied investigation data only. "
            "No API calls, SSH commands, external lookups, or file writes were performed."
        ),
    }


def _build_executive_report_sections(extracted: dict) -> dict:
    """Build a short, non-technical executive incident brief."""
    risk_level = extracted.get("risk_level", "unknown")
    confidence_score = extracted.get("confidence_score", 0)
    escalation_needed = risk_level == "high" or confidence_score >= 70

    if extracted.get("possible_attack_chain"):
        chain_text = " → ".join(extracted["possible_attack_chain"])
        impact_summary = (
            f"Security activity suggests a multi-stage incident involving {chain_text}. "
            "This may indicate unauthorized access followed by follow-on actions on affected systems."
        )
    elif extracted.get("incident_summary"):
        impact_summary = extracted["incident_summary"]
    else:
        impact_summary = (
            "A security event was reviewed. Additional context is needed to confirm business impact."
        )

    executive_summary = (
        f"{impact_summary} Overall risk is {risk_level} with analyst confidence "
        f"{confidence_score}/100. "
    )
    if escalation_needed:
        executive_summary += (
            "Leadership should be notified and incident response coordination is advised."
        )
    else:
        executive_summary += (
            "The security team should continue monitoring while validating scope and impact."
        )

    if extracted.get("possible_attack_chain"):
        technical_summary = (
            f"Activity progressed through: {' → '.join(extracted['possible_attack_chain'])}."
        )
    else:
        technical_summary = (
            "Detailed technical indicators were not included in this executive brief."
        )

    high_level_actions = []
    for step in extracted.get("recommended_next_steps", [])[:4]:
        lowered = step.lower()
        if any(
            term in lowered
            for term in (
                "generate_",
                "kql",
                "opensearch",
                "wazuh",
                "defender",
                "sentinel",
                "qradar",
                "aql",
            )
        ):
            high_level_actions.append(
                "Coordinate with the security team to validate scope and contain affected assets."
            )
        else:
            high_level_actions.append(step)
    if not high_level_actions:
        high_level_actions = [
            "Validate whether business-critical systems are affected.",
            "Confirm containment options with the security operations team.",
        ]

    detection_opportunities = []
    if extracted.get("detection_gaps"):
        detection_opportunities.append(
            "Detection coverage should be reviewed to reduce blind spots for similar activity."
        )

    return {
        "report_title": _report_title("executive", extracted),
        "executive_summary": executive_summary,
        "technical_summary": technical_summary,
        "incident_timeline": extracted.get("attack_timeline", []),
        "affected_assets": _extract_affected_assets(extracted),
        "observables": _extract_observables_list(extracted)[:5],
        "mitre_mapping": extracted.get("mitre_mapping", []),
        "risk_assessment": _risk_assessment_dict(extracted, escalation_needed),
        "containment_recommendations": high_level_actions,
        "detection_opportunities": detection_opportunities,
        "lessons_learned": [
            "Early cross-team communication reduces business disruption during security incidents."
        ],
        "analyst_notes": (
            "Executive incident brief generated from supplied investigation data only. "
            "Technical tool outputs and query details were intentionally omitted."
        ),
    }


def _build_technical_report_sections(extracted: dict) -> dict:
    """Build a detailed technical incident report for analysts and detection engineers."""
    risk_level = extracted.get("risk_level", "unknown")
    confidence_score = extracted.get("confidence_score", 0)
    escalation_needed = risk_level == "high" or confidence_score >= 70

    technical_parts = []
    if extracted.get("correlation_summary"):
        technical_parts.append(f"Correlation findings: {extracted['correlation_summary']}")
    if extracted.get("workflow_used"):
        workflow_text = " → ".join(extracted["workflow_used"])
        technical_parts.append(f"Workflow used: {workflow_text}.")
    if extracted.get("possible_attack_chain"):
        technical_parts.append(
            f"Attack chain: {' → '.join(extracted['possible_attack_chain'])}."
        )
    if extracted.get("attack_timeline"):
        technical_parts.append(
            f"Attack timeline includes {len(extracted['attack_timeline'])} step(s)."
        )

    runbook = extracted.get("runbook")
    if isinstance(runbook, dict):
        if runbook.get("investigation_steps"):
            technical_parts.append(
                f"Primary runbook defines {len(_coerce_list(runbook['investigation_steps']))} investigation step(s)."
            )
        else:
            runbook_step_count = sum(
                len(_coerce_list(entry.get("investigation_steps")))
                for entry in runbook.values()
                if isinstance(entry, dict)
            )
            if runbook_step_count:
                technical_parts.append(
                    f"Correlated runbooks define {runbook_step_count} investigation step(s)."
                )

    ticket_note = extracted.get("ticket_note")
    if isinstance(ticket_note, str) and ticket_note.strip():
        technical_parts.append("Ticket note content is available for analyst documentation.")
    elif isinstance(ticket_note, dict) and ticket_note:
        technical_parts.append("Structured ticket note metadata is available for export.")

    if not technical_parts:
        technical_parts.append(
            "Technical incident context was limited; provide investigation or correlation output for richer detail."
        )

    detection_opportunities = list(extracted.get("detection_gaps", []))
    detection_opportunities.extend(extracted.get("detection_opportunities", []))

    executive_summary = (
        f"Technical review of a {risk_level} severity incident with confidence "
        f"{confidence_score}/100. "
    )
    if extracted.get("incident_summary"):
        executive_summary += extracted["incident_summary"]
    else:
        executive_summary += "Investigation outputs were formatted into a technical incident report."

    return {
        "report_title": _report_title("technical", extracted),
        "executive_summary": executive_summary,
        "technical_summary": " ".join(technical_parts),
        "incident_timeline": extracted.get("attack_timeline", []),
        "affected_assets": _extract_affected_assets(extracted),
        "observables": _extract_observables_list(extracted),
        "mitre_mapping": extracted.get("mitre_mapping", []),
        "risk_assessment": _risk_assessment_dict(extracted, escalation_needed),
        "containment_recommendations": extracted.get("recommended_next_steps", []),
        "detection_opportunities": detection_opportunities,
        "lessons_learned": _default_lessons_learned(extracted),
        "analyst_notes": (
            "Technical incident report generated from supplied investigation data only. "
            "No API calls, SSH commands, external lookups, or file writes were performed."
        ),
    }


def _assemble_incident_report(extracted: dict, report_type: str) -> dict:
    """Select a report builder and return the final structured report dict."""
    if report_type == "executive":
        sections = _build_executive_report_sections(extracted)
    elif report_type == "technical":
        sections = _build_technical_report_sections(extracted)
    else:
        sections = _build_soc_report_sections(extracted)

    return {
        "status": "ok",
        "report_type": report_type,
        **sections,
    }


@mcp.tool()
def generate_incident_report(
    incident_data: dict,
    report_type: str = "soc",
) -> str:
    """
    Generate a structured SOC, executive, or technical incident report from
    investigation or correlation results. Accepts output from
    investigate_security_incident, investigate_ssh_alert,
    investigate_command_execution, or correlate_security_events.

    report_type values:
    - soc: balanced analyst report with timeline, observables, and next steps
    - executive: short business-impact summary without low-level tool details
    - technical: detailed report for analysts and detection engineers

    Unsupported report_type values default to soc. No API calls, SSH commands,
    external lookups, or file writes are performed.
    """
    if not isinstance(incident_data, dict):
        return json.dumps(
            {
                "status": "error",
                "analyst_notes": "incident_data must be a dictionary of investigation results.",
            },
            indent=2,
        )

    normalized_type = (report_type or "soc").strip().lower()
    if normalized_type not in _SUPPORTED_REPORT_TYPES:
        normalized_type = "soc"

    extracted = _extract_incident_fields(incident_data)
    result = _assemble_incident_report(extracted, normalized_type)
    return json.dumps(result, indent=2)


# --- Remote host inventory (read-only SSH) ---

_INVENTORY_SEP = "---SEP---"
_UNSAFE_HOST_CHARS = re.compile(r"[^\w.\-]")


def _normalize_host(host: str) -> str:
    """Validate host input for SSH (strip, blank default, reject unsafe chars).

    Does not read ~/.ssh/config, does not resolve aliases, and does not build
    user@host strings. The returned value is passed verbatim to ssh.
    """
    ssh_host = (host or "").strip()
    if not ssh_host:
        ssh_host = "aihost"
    if _UNSAFE_HOST_CHARS.search(ssh_host):
        raise ValueError(
            f"Invalid host '{host}': only letters, digits, dots, hyphens, "
            "and underscores are allowed."
        )
    return ssh_host


def _run_ssh_readonly(
    host: str,
    remote_command: str,
    timeout: int = 15,
) -> dict:
    """Run a single read-only command on a remote host via SSH (no shell=True)."""
    try:
        # host is passed verbatim to ssh; only strip/default validation happens upstream
        completed = subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                host,
                remote_command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "stdout": "",
            "stderr": f"SSH command timed out after {timeout} seconds.",
            "returncode": -1,
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "stdout": "",
            "stderr": "ssh command not found on this system.",
            "returncode": -1,
        }

    return {
        "ok": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "returncode": completed.returncode,
    }


def _parse_os_release(text: str) -> str:
    pretty_name = ""
    name = ""
    version = ""
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty_name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("NAME=") and not line.startswith("VERSION"):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION="):
            version = line.split("=", 1)[1].strip().strip('"')
    if pretty_name:
        return pretty_name
    if name and version:
        return f"{name} {version}"
    return name or version or ""


def _parse_lscpu(text: str) -> tuple[str, int]:
    cpu_model = ""
    cpu_cores = 0
    for line in text.splitlines():
        if line.startswith("Model name:"):
            cpu_model = line.split(":", 1)[1].strip()
        elif line.startswith("CPU(s):"):
            try:
                cpu_cores = int(line.split(":", 1)[1].strip())
            except ValueError:
                cpu_cores = 0
    return cpu_model, cpu_cores


def _parse_free_m(text: str) -> int:
    for line in text.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return 0
    return 0


def _parse_df_root(text: str) -> str:
    lines = [line for line in text.strip().splitlines() if line.strip()]
    if len(lines) < 2:
        return ""
    parts = lines[-1].split()
    if len(parts) >= 5:
        used = parts[2]
        total = parts[1]
        pct = parts[4]
        return f"{used}/{total} ({pct})"
    return lines[-1]


def _parse_loadavg(text: str) -> dict:
    parts = text.strip().split()
    if len(parts) >= 3:
        return {"1m": parts[0], "5m": parts[1], "15m": parts[2]}
    return {"1m": "", "5m": "", "15m": ""}


def _parse_who_users(text: str) -> list[str]:
    users: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        username = line.split()[0]
        if username not in seen:
            seen.add(username)
            users.append(username)
    return users


def _parse_who_boot(text: str) -> str:
    for line in text.splitlines():
        if "system boot" in line.lower():
            return line.split("system boot", 1)[1].strip()
    return text.strip()


def _empty_inventory() -> dict:
    return {
        "hostname": "",
        "operating_system": "",
        "kernel_version": "",
        "uptime": "",
        "cpu_model": "",
        "cpu_cores": 0,
        "total_memory_mb": 0,
        "disk_usage_root": "",
        "load_average": {"1m": "", "5m": "", "15m": ""},
        "logged_in_users": [],
        "last_boot_time": "",
    }


def _build_inventory_remote_script() -> str:
    """Build a single remote shell script with delimiter-separated read-only commands."""
    commands = [
        "hostname",
        "uname -r",
        "uptime -p",
        "lscpu",
        "free -m",
        "df -h /",
        "cat /proc/loadavg",
        "who",
        "who -b",
        "cat /etc/os-release",
    ]
    parts = []
    for cmd in commands:
        parts.append(cmd)
        parts.append(f"echo {_INVENTORY_SEP}")
    return "; ".join(parts)


@mcp.tool()
def get_system_inventory(host: str = "aihost") -> str:
    """
    Collect system inventory and uptime information from a remote Linux host
    using safe, read-only SSH commands.

    Default host is 'aihost'. Requires key-based SSH access (BatchMode) from
    the machine running this MCP server. No API calls, no package installs,
    and no destructive commands are run.
    """
    try:
        ssh_host = _normalize_host(host)
    except ValueError as exc:
        return json.dumps(
            {
                "status": "error",
                "host": host,
                "inventory": _empty_inventory(),
                "summary": str(exc),
                "analyst_note": (
                    "Host validation failed before any SSH command was run. "
                    "Use a simple hostname or SSH config alias such as 'aihost'."
                ),
            },
            indent=2,
        )

    remote_script = _build_inventory_remote_script()
    ssh_result = _run_ssh_readonly(ssh_host, remote_script, timeout=30)

    if not ssh_result["ok"]:
        stderr = ssh_result["stderr"].strip()
        summary = (
            f"Failed to collect inventory from {ssh_host} via SSH."
        )
        if stderr:
            summary += f" {stderr}"
        return json.dumps(
            {
                "status": "error",
                "host": ssh_host,
                "inventory": _empty_inventory(),
                "summary": summary,
                "analyst_note": (
                    "SSH connection or remote command failed. Verify that "
                    f"'ssh {ssh_host} hostname' works from this machine, "
                    "that key-based authentication is configured, and that the "
                    "host is reachable. This tool runs read-only commands only; "
                    "no API calls are made."
                ),
            },
            indent=2,
        )

    segments = ssh_result["stdout"].split(_INVENTORY_SEP)
    # Trailing echo produces an extra empty segment after the last command.
    segments = [seg.strip() for seg in segments if seg.strip()]

    inventory = _empty_inventory()
    if len(segments) >= 1:
        inventory["hostname"] = segments[0]
    if len(segments) >= 2:
        inventory["kernel_version"] = segments[1]
    if len(segments) >= 3:
        inventory["uptime"] = segments[2]
    if len(segments) >= 4:
        cpu_model, cpu_cores = _parse_lscpu(segments[3])
        inventory["cpu_model"] = cpu_model
        inventory["cpu_cores"] = cpu_cores
    if len(segments) >= 5:
        inventory["total_memory_mb"] = _parse_free_m(segments[4])
    if len(segments) >= 6:
        inventory["disk_usage_root"] = _parse_df_root(segments[5])
    if len(segments) >= 7:
        inventory["load_average"] = _parse_loadavg(segments[6])
    if len(segments) >= 8:
        inventory["logged_in_users"] = _parse_who_users(segments[7])
    if len(segments) >= 9:
        inventory["last_boot_time"] = _parse_who_boot(segments[8])
    if len(segments) >= 10:
        inventory["operating_system"] = _parse_os_release(segments[9])

    load = inventory["load_average"]
    user_count = len(inventory["logged_in_users"])
    summary = (
        f"Host {inventory['hostname'] or ssh_host} "
        f"({inventory['operating_system'] or 'unknown OS'}) — "
        f"uptime {inventory['uptime'] or 'unknown'}, "
        f"{inventory['cpu_cores']} CPU core(s), "
        f"{inventory['total_memory_mb']} MB RAM, "
        f"root disk {inventory['disk_usage_root'] or 'unknown'}, "
        f"load {load['1m']}/{load['5m']}/{load['15m']}, "
        f"{user_count} logged-in user(s)."
    )

    analyst_note = (
        "This tool collects read-only system facts via SSH for baseline host "
        "context before investigations or detections. It extracts inventory "
        "only; the AI should interpret anomalies, compare against expected "
        "baselines, and determine severity. Assumes key-based SSH to the "
        "target host. No API calls or destructive commands are run from this "
        "MCP server."
    )

    result = {
        "status": "ok",
        "host": ssh_host,
        "inventory": inventory,
        "summary": summary,
        "analyst_note": analyst_note,
    }

    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run()
