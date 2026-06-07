# AI Agent MCP Lab

A hands-on learning lab for understanding AI Agents, the Model Context Protocol (MCP), and AI-assisted Security Operations Center (SOC) workflows.

This project was built to learn how AI agents use tools, how MCP servers expose capabilities to AI models, and how security workflows can be automated using custom Python-based MCP tools.

---

# Project Goals

This lab focuses on:

- Learning AI Agent fundamentals
- Understanding MCP architecture
- Building custom MCP servers with Python
- Creating AI-assisted security workflows
- Practicing SOC investigation automation
- Developing reusable security tooling

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

# Architecture

```text
Wazuh Alert JSON
        │
        ▼
parse_wazuh_alert
        │
        ▼
score_ssh_alert
        │
        ▼
generate_investigation_summary
        │
        ▼
investigate_ssh_alert
        │
        ▼
SOC Investigation Package
```

Additional investigation tools:

```text
generate_wazuh_query
generate_defender_kql
```

These assist analysts with hunting and correlation activities.

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
│   └── wazuh_alert.json
├── scripts/
│   └── soc_mcp_server.py
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

# MCP Tools

## parse_wazuh_alert

Purpose:

- Parse Wazuh alert JSON
- Extract observables
- Normalize fields for investigations

Output:

- Source IP
- Target User
- Host
- Rule Information
- Raw Log

---

## score_ssh_alert

Purpose:

Assign severity and confidence scores using rule-based logic.

Inputs:

- Source IP
- Target User
- Rule Level
- Failure Count
- Success After Failure
- Known Admin Host

Outputs:

- Severity
- Confidence Score
- Priority
- Recommended Next Steps

---

## generate_wazuh_query

Purpose:

Generate OpenSearch/Wazuh hunting queries.

Outputs:

- OpenSearch JSON query
- Simple filter syntax
- Investigation guidance

---

## generate_defender_kql

Purpose:

Generate Microsoft Defender and Sentinel hunting queries.

Outputs:

- Defender Advanced Hunting KQL
- Sentinel Syslog KQL
- Investigation guidance

---

## generate_investigation_summary

Purpose:

Create analyst-ready investigation summaries.

Outputs:

- Executive Summary
- Risk Assessment
- Recommended Actions
- Analyst Notes

---

## investigate_ssh_alert

Purpose:

Orchestrate a complete investigation workflow.

Internally calls:

```text
parse_wazuh_alert
      ↓
score_ssh_alert
      ↓
generate_investigation_summary
```

Returns:

```json
{
  "alert_summary": {},
  "risk_score": {},
  "investigation_summary": {}
}
```

---

# Example Workflow

Input:

```text
sample_data/wazuh_alert.json
```

Workflow:

```text
Alert
  ↓
Parse
  ↓
Score
  ↓
Summarize
  ↓
Investigation Package
```

Example Output:

```text
Severity: High
Confidence: 80
Priority: P2

Root account targeted
15 failed logins in 10 minutes
Potential brute-force activity
```

---

# Key Security Concepts Practiced

- Alert Triage
- Incident Prioritization
- Security Automation
- Detection Engineering
- Wazuh Investigations
- OpenSearch Queries
- Microsoft Defender Hunting
- Sentinel Hunting
- AI-Assisted SOC Workflows
- MCP Tool Orchestration

---

# Future Enhancements

Planned additions:

- CrowdStrike query generation
- QRadar AQL generation
- Splunk SPL generation
- Threat intelligence enrichment
- Asset inventory lookups
- IOC enrichment
- Multi-alert correlation
- Real API integrations
- AI-hosted MCP services
- Integration with future AI lab infrastructure

---

# Lessons Learned

The most important takeaway from this lab:

```text
AI reasons.
MCP tools perform actions.
Workflows combine tools into useful outcomes.
```

This project demonstrates how AI agents can augment security operations by combining reasoning, structured tooling, and repeatable workflows.

## Current Status

This project currently includes a working custom Python MCP server with multiple SOC-focused tools and one orchestrated SSH alert investigation workflow.

The lab is currently local-only and does not connect to production security tools or external APIs.

## Current Workflow Output

The `investigate_ssh_alert` tool returns a complete SOC triage package:

- Alert summary
- Risk score
- Investigation summary
- Recommended Wazuh/OpenSearch query
- Recommended Defender/Sentinel queries

This allows an analyst to move from a raw Wazuh alert to a structured investigation package in one MCP tool call.

## Current MCP Tools

### identify_alert_type

Purpose:

Classify Wazuh alerts and recommend the correct investigation workflow.

Current classifications:

| Alert Type       | Workflow              |
| ---------------- | --------------------- |
| ssh_auth_failure | investigate_ssh_alert |
| unknown          | manual_review         |

Example:

```json
{
  "alert_type": "ssh_auth_failure",
  "recommended_workflow": "investigate_ssh_alert",
  "confidence": "high"
}
```

---

### parse_wazuh_alert

Purpose:

Parse Wazuh alert JSON and extract security observables.

Extracted fields include:

- Source IP
- Source Port
- Target User
- Host
- Rule Information
- Decoder
- Raw Log

---

### score_ssh_alert

Purpose:

Assign severity, confidence, and priority using rule-based logic.

Factors currently include:

- Failed login activity
- Root account targeting
- Brute-force volume
- Success after failure
- Known administrative source hosts

Outputs:

- Severity
- Confidence Score
- Priority
- Recommended Next Steps

---

### generate_wazuh_query

Purpose:

Generate OpenSearch/Wazuh hunting queries.

Outputs:

- OpenSearch JSON query
- Discover filter syntax
- Analyst guidance

---

### generate_defender_kql

Purpose:

Generate Microsoft Defender and Sentinel hunting queries.

Outputs:

- Defender Advanced Hunting query
- Sentinel Syslog query
- Investigation guidance

---

### generate_investigation_summary

Purpose:

Create analyst-ready investigation summaries.

Outputs:

- Executive Summary
- Risk Assessment
- Recommended Actions
- Analyst Notes

---

### generate_soc_ticket_note

Purpose:

Generate ticket-ready notes for:

- ServiceNow
- Jira
- IBM SOAR
- Other case management platforms

Outputs:

- Summary
- Observables
- Severity/Priority
- Analysis
- Recommended Actions
- Next Steps

---

### recommend_next_action

Purpose:

Recommend analyst actions based on severity and confidence.

Examples:

| Confidence | Recommendation                        |
| ---------- | ------------------------------------- |
| >= 80      | Escalate and begin containment review |
| 60-79      | Gather additional evidence            |
| < 60       | Continue investigation                |

Outputs:

- Recommended Action
- Reasoning
- Recommended Tool
- Analyst Guidance

---

### investigate_ssh_alert

Purpose:

Perform a complete SSH authentication failure investigation workflow.

Workflow:

```text
Wazuh Alert
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
Return Complete Investigation Package
```

Returns:

```json
{
  "alert_summary": {},
  "risk_score": {},
  "investigation_summary": {},
  "recommended_queries": {},
  "next_action": {}
}
```

---

## Current Investigation Workflow

```text
Raw Wazuh Alert
        │
        ▼
identify_alert_type
        │
        ▼
investigate_ssh_alert
        │
        ▼
Alert Summary
Risk Score
Investigation Summary
Recommended Queries
Next Action
```

---

## Current Status

Implemented:

- Custom Python MCP Server
- Wazuh Alert Parsing
- SSH Authentication Failure Investigation
- Severity Scoring
- OpenSearch Query Generation
- Defender/Sentinel Query Generation
- Investigation Summary Generation
- Ticket Note Generation
- Analyst Decision Recommendations
- Alert Type Routing

The project currently supports:

- SSH Authentication Failure investigations

Planned future support:

- Malware Detection
- Suspicious PowerShell Activity
- Privilege Escalation
- Persistence Mechanisms
- Threat Intelligence Enrichment
- Multi-alert Correlation
- Detection Engineering Recommendations
- Additional SIEM Platforms (QRadar, Splunk)

```

```

---

# Author

Sydney McGee

Cybersecurity Analyst | Security Automation Enthusiast | AI Security Engineering Learner

Current focus:

- AI Agents
- MCP
- Security Automation
- Detection Engineering
- SOC Workflow Engineering
