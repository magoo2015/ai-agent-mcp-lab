# SOC Investigation Tools — Offline CLI + MCP stdio (v1)

Sample-data-driven security investigation tools for the AI Security Engineering Platform. This module accepts structured alert JSON and returns analyst-ready investigation packages — **without** connecting to live SIEM, EDR, or email security APIs.

Two entry points share the same deterministic core:

| Entry point | Role |
| ----------- | ---- |
| `main.py` | Offline CLI — read a JSON alert file, print investigation JSON to stdout |
| `mcp_server.py` | MCP stdio server — expose the same tools over the Model Context Protocol |

## Offline CLI vs MCP server

| | Offline CLI (`main.py`) | MCP server (`mcp_server.py`) |
| - | ----------------------- | ---------------------------- |
| Transport | Local process / Docker one-shot | MCP JSON-RPC over **stdio** |
| Input | Path to alert JSON file | Structured tool arguments from an MCP client |
| Output | Pretty/compact JSON on stdout | MCP tool results (protocol messages on stdout) |
| Tools | `investigate_alert` only (via CLI) | `investigate_alert`, `map_mitre`, `generate_queries` |
| Use case | Regression tests, demos, scripts | Cursor / Claude Desktop / other MCP hosts |

Both paths call the same modules under `tools/` and `schemas/`. The MCP layer is transport, validation, registration, and serialization only — it does not reimplement investigation logic.

## Why offline?

This lab does not have live access to QRadar, Microsoft Defender, Sentinel, CrowdStrike, Proofpoint, or Wazuh APIs. v1 is intentionally **offline and deterministic** so you can:

- Demonstrate SOC automation design in portfolios and interviews
- Test alert normalization and investigation workflows safely
- Expose tools via real MCP stdio without production-system credentials

No live SIEM/EDR access is required. All examples run against bundled sample alerts. The AI Gateway is **not** called from this module.

## MCP architecture

```
MCP client (Cursor, test_mcp_client.py, …)
  ↓ stdio / JSON-RPC
mcp_server.py  (soc-investigation-tools)
  ↓
existing deterministic SOC tools
  ├── investigate_alert
  ├── map_mitre
  └── generate_queries
```

- **No network ports** — the server speaks only over stdin/stdout.
- **Official Python MCP SDK** (`mcp`) — no hand-rolled JSON-RPC.
- **Server name:** `soc-investigation-tools`

### Available MCP tools

| Tool | Input | Output |
| ---- | ----- | ------ |
| `investigate_alert` | `AlertInput` fields (`platform`, `alert_type`, `severity`, `description`, `observables`, optional `raw_event`) | Full investigation package: `summary`, `severity_assessment`, `mitre`, `recommended_queries`, `next_steps`, `detection_opportunities`, `confidence`, `limitations` |
| `map_mitre` | `alert_type`, `description`, optional `observables` | `technique_id`, `technique_name`, `tactic`, `confidence`, `rationale` |
| `generate_queries` | Structured `observables` + alert context (`alert_type`, optional `platform` / `severity` / `description`) | `qradar_aql`, `sentinel_kql`, `defender_advanced_hunting_kql`, `opensearch_dql` |

### Stdio transport behavior

MCP over stdio multiplexes protocol frames on the process pipes:

- **stdout** — reserved exclusively for MCP JSON-RPC messages
- **stderr** — Python logging (startup, tool invocations, errors)
- **stdin** — MCP client requests

**Why stdout must remain protocol-only:** any banner, `print()`, debug dump, or accidental JSON sample on stdout corrupts the JSON-RPC stream and breaks the client session. Never log `raw_event` or sensitive observables by default.

## Quick start

### Docker — offline CLI (regression)

```bash
cd platform

docker compose --profile mcp run --rm mcp-server \
  python main.py sample_data/ssh_failed_login.json

docker compose --profile mcp run --rm mcp-server \
  python main.py sample_data/defender_suspicious_process.json

docker compose --profile mcp run --rm mcp-server \
  python main.py sample_data/proofpoint_phishing.json

docker compose --profile mcp run --rm mcp-server \
  python main.py sample_data/insufficient_evidence.json
```

### Docker — MCP stdio server

```bash
cd platform

docker compose --profile mcp run --rm -i mcp-server python mcp_server.py
```

### Docker — MCP client transport test

```bash
cd platform

docker compose --profile mcp run --rm mcp-server \
  python test_mcp_client.py
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

# Offline CLI
python main.py sample_data/ssh_failed_login.json

# MCP server (stdio — typically launched by a client, not interactively)
python mcp_server.py

# MCP client self-test
python test_mcp_client.py
```

## End-to-End Investigation Demo

`demo_investigation.py` loads a normalized alert JSON, starts `mcp_server.py` over stdio, calls `investigate_alert`, builds one `InvestigationReport`, and renders Markdown and optional standalone HTML. By default Markdown goes to stdout; use `-o` / `--output` and `--html-output` to write files. The MCP container has no default host `docs/` mount—mount `docs/demo-output` to `/output` when writing gallery artifacts. No live SIEM credentials are required. There is no automated PDF flag; PDF is a manual browser print of the HTML.

### Gallery scenarios (expected dispositions)

| Scenario | Sample input | Expected disposition | Gallery artifacts |
| -------- | ------------ | -------------------- | ----------------- |
| SSH Failed Login | `sample_data/ssh_failed_login.json` | Suspicious Activity | `ssh-failed-login-investigation.md` / `.html` / `.pdf` |
| Phishing Email | `sample_data/proofpoint_phishing.json` | Suspicious Activity | `phishing-email-investigation.md` / `.html` |
| Suspicious Process | `sample_data/defender_suspicious_process.json` | Suspicious Activity | `suspicious-process-investigation.md` / `.html` |
| Insufficient Evidence | `sample_data/insufficient_evidence.json` | Insufficient Evidence | `insufficient-evidence-investigation.md` / `.html` |

Index: [docs/demo-output/README.md](../../docs/demo-output/README.md).

```bash
cd platform
docker compose --profile mcp build mcp-server
```

```bash
docker compose --profile mcp run --rm mcp-server \
  python demo_investigation.py
```

One investigation produces both Markdown and HTML (volume mount required for host files):

```bash
docker compose --profile mcp run --rm \
  -v "$(pwd)/../docs/demo-output:/output" \
  mcp-server \
  python demo_investigation.py \
    sample_data/ssh_failed_login.json \
    -o /output/ssh-failed-login-investigation.md \
    --html-output /output/ssh-failed-login-investigation.html
```

```bash
docker compose --profile mcp run --rm \
  -v "$(pwd)/../docs/demo-output:/output" \
  mcp-server \
  python demo_investigation.py \
    sample_data/proofpoint_phishing.json \
    -o /output/phishing-email-investigation.md \
    --html-output /output/phishing-email-investigation.html
```

```bash
docker compose --profile mcp run --rm \
  -v "$(pwd)/../docs/demo-output:/output" \
  mcp-server \
  python demo_investigation.py \
    sample_data/defender_suspicious_process.json \
    -o /output/suspicious-process-investigation.md \
    --html-output /output/suspicious-process-investigation.html
```

```bash
docker compose --profile mcp run --rm \
  -v "$(pwd)/../docs/demo-output:/output" \
  mcp-server \
  python demo_investigation.py \
    sample_data/insufficient_evidence.json \
    -o /output/insufficient-evidence-investigation.md \
    --html-output /output/insufficient-evidence-investigation.html
```

Browser print-to-PDF: open the HTML locally → File → Print → Save as PDF. Only the SSH PDF is committed as a sample.
## Connecting from Cursor (or another MCP client)

Use a configuration that launches the Dockerized stdio server. Do **not** hardcode host-specific absolute paths; run the client command from the `platform` directory (or set the client's working-directory option to `platform` if supported):

```json
{
  "mcpServers": {
    "soc-investigation-tools": {
      "command": "docker",
      "args": [
        "compose",
        "--profile",
        "mcp",
        "run",
        "--rm",
        "-i",
        "mcp-server",
        "python",
        "mcp_server.py"
      ]
    }
  }
}
```

The MCP client must execute this from the `platform` directory so `docker compose` finds `docker-compose.yml`, unless the host UI provides an explicit working-directory setting.

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

## What it does (modules)

| Component | Role |
| --------- | ---- |
| `schemas/alert_schema.py` | Pydantic models for alert input and investigation output |
| `tools/investigate_alert.py` | Main tool — orchestrates MITRE mapping, queries, and analyst guidance |
| `tools/mitre_mapper.py` | Deterministic MITRE ATT&CK mappings by `alert_type` |
| `tools/query_generator.py` | Example investigation pivots (QRadar AQL, Sentinel KQL, Defender KQL, OpenSearch/DQL) |
| `mcp_server.py` | Official MCP SDK stdio transport + tool registration |
| `test_mcp_client.py` | Stdio client smoke test |
| `demo_investigation.py` | End-to-end MCP demo — alert JSON → Markdown SOC report |
| `sample_data/` | Offline alert fixtures (SSH, phishing, suspicious process, insufficient evidence) |

Confidence scores and MITRE mappings are **conservative by design** — the framework does not overstate certainty.

## Security boundaries and limitations

- **No live production-system access** — no QRadar, Defender, Sentinel, CrowdStrike, Proofpoint, or Wazuh API calls
- **No AI Gateway** — this phase does not call `platform/ai-gateway/`
- **No published ports** — MCP uses stdio only
- **No host package changes** — dependencies install inside the container image
- MITRE mappings are rule-based, not threat-intel enriched
- Query examples are pivots, not validated against your log schema
- No live enrichment (WHOIS, VT, internal CMDB)
- Do not log `raw_event` or sensitive observables unless required for an error message

## Adding real connectors later

The offline design keeps integration points explicit:

1. **Ingest adapters** — Map vendor webhooks/API payloads → `AlertInput`
2. **Live query backends** — Replace or augment `query_generator.py` with executed queries
3. **AI Gateway** — Optional LLM enrichment for narrative summaries
4. **Network MCP transports** — Only if a future phase explicitly requires them; stdio remains the default for local hosts

Keep adapters behind interfaces so offline CLI and MCP tests continue to pass without credentials.

## Portfolio / interview talking points

- **Real MCP transport** — official Python SDK + stdio, not a mock protocol
- **Structured analyst handoff** — JSON suitable for tickets, SOAR, or LLM context
- **Defense in depth** — MITRE framing, hunt queries, detection ideas, and explicit limitations
- **Honest automation** — confidence scores and limitation notes model responsible AI-assisted SOC design
- **Platform thinking** — fits the broader AI Security Engineering Platform without coupling to live vendors yet

## Related documentation

- [Demo gallery](../../docs/demo-output/README.md)
- [Platform README](../README.md)
- [Root README](../../README.md)
- [Prompt library — MITRE mapping](../prompts/mitre_mapping.md)
- [Architecture](../docs/architecture.md)
