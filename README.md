# AI Agent MCP Lab

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-555)
![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?logo=prometheus&logoColor=white)
![Grafana](https://img.shields.io/badge/Grafana-F46800?logo=grafana&logoColor=white)

An AI Security Engineering lab for practicing SOC investigation automation, Model Context Protocol (MCP), AI Gateway design, prompt evaluation, observability, and detection engineering in a controlled environment—without live SIEM, EDR, or production APIs.

The repository contains two major workflows:

1. **AI Platform** — Self-hosted runtime on Docker Compose behind Nginx: Open WebUI for chat, a FastAPI AI Gateway for programmatic model access (Ollama locally, optional OpenAI), and Prometheus/Grafana for host and container metrics. Inference is optional via an `ai` profile so a small VPS can keep the UI and observability stack lightweight when models are not needed.

2. **SOC Investigation Engine** — Offline MCP server that accepts normalized alert JSON (for example Wazuh SSH failures, Defender suspicious process, or Proofpoint phishing samples), maps activity to MITRE ATT&CK, drafts multi-SIEM hunt queries, and returns analyst-ready packages as Markdown SOC reports. Tools are bounded and deterministic for safe demos and regression testing.

A SOC analyst prompt library and promptfoo evaluation suite sit alongside the gateway so prompt quality can be tested against the same inference path used in the lab.

![Architecture Overview](docs/images/architecture-overview.svg)

## Features

### AI Platform

- **AI Gateway** — FastAPI proxy with API-key protection, request limits, and Prometheus metrics
- **Ollama** — Local LLM inference (Compose `ai` profile; default model `tinyllama`)
- **Optional OpenAI provider** — Gateway routing when `OPENAI_API_KEY` is configured
- **Open WebUI** — Browser chat UI proxied through Nginx

### Security Investigation

- **MCP Investigation Engine** — Offline stdio MCP server (`investigate_alert`, `map_mitre`, `generate_queries`)
- **MITRE Mapping** — Evidence-linked ATT&CK technique mapping from alert context
- **Investigation Reports** — Structured packages with Markdown SOC report demos and standalone offline HTML
- **Browser PDF export** — Print the HTML report from a browser (Save as PDF); no separate PDF renderer in the service
- **Query Generation** — QRadar AQL, Microsoft Defender KQL, Sentinel KQL, and OpenSearch DQL drafts
- **Detection Recommendations** — Detection opportunities and next-step guidance per alert type

### Detection Engineering

- Alert-type detection opportunity lists (SSH brute force, suspicious process, phishing, and related cases)
- Multi-SIEM investigation and hunt query drafts for analyst handoff
- Sample-driven workflows suitable for review, tuning, and conversion—not auto-deployed rules

### Observability

- Prometheus metrics collection (Node Exporter, cAdvisor, self-scrape, AI Gateway `/metrics`)
- Grafana dashboards UI behind Nginx at `/grafana/`
- Core vs `ai` profile split for capacity-aware operation on small VPS hosts

### Prompt Evaluation

- SOC prompt templates (alert summary, MITRE mapping, detection recommendation, executive summary)
- promptfoo evaluation against the AI Gateway (`eval` Compose profile)

## Report Outputs

The investigation platform supports:

- **Markdown** investigation reports
- **Standalone offline HTML** reports
- **Browser-generated PDF** reports

PDF files are produced by printing the standalone HTML report through a browser. This avoids introducing a second report renderer or a heavyweight PDF dependency into the MCP service.

Examples:

- [docs/demo-output/ssh-failed-login-investigation.html](docs/demo-output/ssh-failed-login-investigation.html)
- [docs/demo-output/ssh-failed-login-investigation.pdf](docs/demo-output/ssh-failed-login-investigation.pdf)

Workflow detail: [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) (Version 1.1 Phase 7 — Browser Print-to-PDF Export).

## Architecture

Public traffic enters through Nginx. Open WebUI and Grafana are served on distinct paths; programmatic model calls go through the AI Gateway to Ollama or optional OpenAI.

```text
Internet
  ↓
Nginx
  ↓
Open WebUI / Grafana
  ↓
AI Gateway
  ↓
Ollama / OpenAI
```

Investigations follow a separate, offline path from alert input to Markdown report:

```text
Alert
  ↓
MCP Investigation
  ↓
Markdown Report
```

Full diagram: [docs/images/architecture-overview.svg](docs/images/architecture-overview.svg).  
Platform detail: [platform/docs/architecture.md](platform/docs/architecture.md).

## Screenshots

Screenshots will be added during the v1.0 release.

## Skills Demonstrated

Python · FastAPI · Docker · Docker Compose · MCP · Promptfoo · Grafana · Prometheus · Nginx · MITRE ATT&CK · QRadar AQL · Microsoft Defender KQL · Sentinel KQL · Detection Engineering · SOC Automation

## Project Structure

```text
ai-agent-mcp-lab/
├── docs/
│   ├── demo-output/              # Sample Markdown, HTML, and PDF SOC reports
│   └── images/                   # Architecture diagrams and README assets
│       └── architecture-overview.svg
├── notes/
│   └── lab_journal.md
├── platform/
│   ├── ai-gateway/               # FastAPI AI Gateway (Ollama + optional OpenAI)
│   ├── mcp-server/               # Offline SOC MCP tools + demo CLI
│   ├── nginx/                    # Reverse proxy config
│   ├── prometheus/               # Scrape config
│   ├── grafana/                  # Grafana volume mount point
│   ├── prompts/                  # SOC analyst prompt templates
│   ├── promptfoo/                # Prompt evaluation config
│   ├── scripts/                  # deploy, start-ai, stop-ai, status, stop
│   ├── docs/                     # Platform architecture and ops docs
│   ├── docker-compose.yml
│   └── .env.example
├── sample_data/                  # Legacy lab alert samples
├── scripts/
│   ├── soc_mcp_server.py         # Extended MCP tool catalog (workstation)
│   └── test_soc_mcp_server.py
├── .cursor/
│   ├── mcp.json
│   └── rules/
├── CHANGELOG.md
├── LICENSE
└── README.md
```

## Quick Start

From `platform/` (copy `.env.example` to `.env` and set `GRAFANA_ADMIN_PASSWORD` first):

```bash
# Core stack: Nginx, Open WebUI, Prometheus, Grafana, exporters
./scripts/deploy.sh

# Optional local inference + AI Gateway
./scripts/start-ai.sh

# Offline MCP investigation demo (Markdown report to stdout)
docker compose --profile mcp run --rm mcp-server \
  python demo_investigation.py sample_data/ssh_failed_login.json
```

Helper scripts and profiles: [platform/README.md](platform/README.md).

## Example Investigation Workflow

```text
Normalized alert JSON
  (e.g. sample_data/ssh_failed_login.json)
        ↓
MCP investigate_alert
        ↓
MITRE mapping + severity/confidence
        ↓
Recommended queries
  (QRadar AQL · Defender KQL · Sentinel KQL · OpenSearch DQL)
        ↓
Detection opportunities + next steps
        ↓
Markdown SOC investigation report
  (docs/demo-output/*.md)
        ↓
Standalone HTML report (optional)
  (docs/demo-output/*.html)
        ↓
Browser Print → Save as PDF (optional)
  (docs/demo-output/*.pdf)
```

Example reports: [docs/demo-output/](docs/demo-output/).

## Current Status

### Completed

- Docker Compose AI security platform (Nginx, Open WebUI, observability)
- AI Gateway with Ollama and optional OpenAI providers
- Offline MCP investigation engine and Markdown report demos
- MITRE mapping and multi-SIEM query generation
- SOC prompt library and promptfoo evaluation against the gateway
- Architecture overview diagram and platform documentation

### In Progress

- HTTPS/TLS activation (ACME bootstrap prepared; certificate issuance pending)
- Expanded Grafana dashboards and basic alerting
- Broader promptfoo scenarios beyond the default SSH suite
- Root documentation polish (this pass)

### Future Ideas

- garak LLM security testing against the AI Gateway
- GitHub Actions CI for MCP tests and linting
- Additional investigation workflows (malware, PowerShell, privilege escalation)
- Optional threat-intel and case-management integrations

## Documentation

| Document | Purpose |
| -------- | ------- |
| [platform/README.md](platform/README.md) | Platform ops, profiles, and quick commands |
| [platform/mcp-server/README.md](platform/mcp-server/README.md) | MCP tools, CLI, and Cursor wiring |
| [platform/docs/architecture.md](platform/docs/architecture.md) | Component and traffic-flow detail |
| [platform/docs/platform-blueprint.md](platform/docs/platform-blueprint.md) | Security model and longer roadmap |
| [platform/docs/prompt-library.md](platform/docs/prompt-library.md) | SOC prompt templates |
| [platform/docs/promptfoo.md](platform/docs/promptfoo.md) | Prompt evaluation setup |

## Author

Sydney McGee

Cybersecurity Analyst · Security Automation · AI Security Engineering
