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
    generate_wazuh_query, generate_defender_kql, and recommend_next_action.

    Returns a complete SOC triage package:
    - alert_summary: parsed observables from the Wazuh alert file
    - risk_score: severity, confidence, priority, and reasoning
    - investigation_summary: executive summary and recommended actions
    - recommended_queries: Wazuh/OpenSearch and Defender/Sentinel KQL examples
    - next_action: recommended investigative step based on severity and confidence

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

    result = {
        "alert_summary": parsed,
        "risk_score": scored,
        "investigation_summary": summary,
        "recommended_queries": {
            "wazuh_opensearch": wazuh_queries,
            "defender_sentinel": defender_queries,
        },
        "next_action": next_action,
    }

    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run()
