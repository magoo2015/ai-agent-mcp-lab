# Offline MCP SOC Tool Framework (v1)

Sample-data-driven security investigation tools designed in the **Model Context Protocol (MCP)** style. This module accepts structured alert JSON and returns analyst-ready investigation packages — **without** connecting to live SIEM, EDR, or email security APIs.

## Why offline?

This lab does not have live access to QRadar, Microsoft Defender, Sentinel, CrowdStrike, or Wazuh APIs. v1 is intentionally **offline and deterministic** so you can:

- Demonstrate SOC automation design in portfolios and interviews
- Test alert normalization and investigation workflows safely
- Evolve toward real MCP server integrations when API credentials and environments are available

No live SIEM/EDR access is required. All examples run against bundled sample alerts.

## What it does

| Component | Role |
| --------- | ---- |
| `schemas/alert_schema.py` | Pydantic models for alert input and investigation output |
| `tools/investigate_alert.py` | Main tool — orchestrates MITRE mapping, queries, and analyst guidance |
| `tools/mitre_mapper.py` | Deterministic MITRE ATT&CK mappings by `alert_type` |
| `tools/query_generator.py` | Example investigation pivots (QRadar AQL, Sentinel KQL, Defender KQL, OpenSearch/DQL) |
| `sample_data/` | Realistic offline alert fixtures (SSH, Defender, Proofpoint) |

### Investigation output

```json
{
  "summary": "...",
  "severity_assessment": "...",
  "mitre": [...],
  "recommended_queries": { "qradar_aql": [...], "sentinel_kql": [...], ... },
  "next_steps": [...],
  "detection_opportunities": [...],
  "confidence": 0,
  "limitations": [...]
}
```

Confidence scores and MITRE mappings are **conservative by design** — the framework does not overstate certainty.

## Quick start

### Docker (recommended — no host Python packages)

```bash
cd platform

docker compose --profile mcp run --rm mcp-server python main.py sample_data/ssh_failed_login.json

docker compose --profile mcp run --rm mcp-server python main.py sample_data/defender_suspicious_process.json

docker compose --profile mcp run --rm mcp-server python main.py sample_data/proofpoint_phishing.json
```

Build the image explicitly (optional):

```bash
cd platform
docker compose --profile mcp build mcp-server
```

### Local Python (optional)

```bash
cd platform/mcp-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python main.py sample_data/ssh_failed_login.json
python main.py sample_data/defender_suspicious_process.json
python main.py sample_data/proofpoint_phishing.json
```

## Alert input schema

```json
{
  "platform": "wazuh",
  "alert_type": "ssh_failed_login",
  "severity": "high",
  "description": "Human-readable summary",
  "observables": {
    "source_ip": "203.0.113.45",
    "destination_ip": "10.0.1.15",
    "hostname": "prod-web-01",
    "username": "root",
    "process_name": null,
    "file_hash": null,
    "url": null,
    "sender": null,
    "recipient": null
  },
  "raw_event": { }
}
```

Supported `alert_type` values for MITRE mapping:

| alert_type | MITRE technique | Confidence |
| ---------- | --------------- | ---------- |
| `ssh_failed_login` | T1110 Brute Force | medium |
| `suspicious_process` | T1059 Command and Scripting Interpreter | medium |
| `phishing_email` | T1566 Phishing | medium |
| `dlp_alert` | T1041 Exfiltration Over C2 Channel | low |
| `aws_iam_change` | T1098 Account Manipulation | medium |

## How this relates to MCP

[MCP (Model Context Protocol)](https://modelcontextprotocol.io/) defines how AI agents discover and invoke tools with structured inputs and outputs. This framework is shaped for future MCP exposure:

1. **Tool boundary** — `investigate_alert` is a single, well-scoped tool with typed I/O
2. **Composable modules** — MITRE mapping and query generation are separate, swappable units
3. **CLI today, MCP server tomorrow** — v1 uses a CLI for easy testing; a network MCP server can wrap the same functions without changing core logic

The existing lab MCP assistant (`scripts/soc_mcp_server.py` in the repo root) can eventually delegate to or be replaced by this modular implementation.

## Adding real connectors later

The offline design keeps integration points explicit:

1. **Ingest adapters** — Map vendor webhooks/API payloads → `AlertInput` (e.g., `WazuhAdapter`, `DefenderAdapter`)
2. **Live query backends** — Replace or augment `query_generator.py` output with executed queries against QRadar, Sentinel, etc.
3. **MCP transport** — Expose `investigate_alert` via `mcp` Python SDK or stdio server for Cursor/Claude Desktop
4. **AI Gateway** — Optional LLM enrichment through `platform/ai-gateway/` for narrative summaries (not required for v1)

Keep adapters behind interfaces so offline tests continue to pass without credentials.

## Portfolio / interview talking points

- **Structured analyst handoff** — JSON output suitable for tickets, SOAR playbooks, or LLM context
- **Defense in depth** — MITRE framing, hunt queries, detection ideas, and explicit limitations
- **Honest automation** — Confidence scores and limitation notes model responsible AI-assisted SOC design
- **Platform thinking** — Fits the broader AI Security Engineering Platform (gateway, prompts, observability, MCP)

## Limitations (v1)

- No network server or MCP stdio transport yet
- MITRE mappings are rule-based, not threat-intel enriched
- Query examples are pivots, not validated against your log schema
- No live enrichment (WHOIS, VT, internal CMDB)

## Related documentation

- [Platform README](../README.md)
- [Prompt library — MITRE mapping](../prompts/mitre_mapping.md)
- [Architecture](../docs/architecture.md)
