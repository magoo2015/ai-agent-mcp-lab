from mcp.server.fastmcp import FastMCP
import json
import re
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
    logic. No SSH commands or API calls.
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
    "suspicious_command_execution": ["T1105", "T1059", "T1027"],
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
    generate_wazuh_query, generate_defender_kql, recommend_next_action, and
    generate_detection_recommendation.

    Returns a complete SOC triage package:
    - alert_summary: parsed observables from the Wazuh alert file
    - risk_score: severity, confidence, priority, and reasoning
    - investigation_summary: executive summary and recommended actions
    - recommended_queries: Wazuh/OpenSearch and Defender/Sentinel KQL examples
    - next_action: recommended investigative step based on severity and confidence
    - detection_recommendations: post-investigation detection engineering guidance

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
    analyst guidance, and detection recommendations. No API calls.
    Reuses generate_detection_recommendation.
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


if __name__ == "__main__":
    mcp.run()
