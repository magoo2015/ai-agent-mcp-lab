# Changelog

All notable changes to the AI Agent MCP Lab and AI Security Engineering Platform.

## [Unreleased]

### Added

- Operational helper scripts under `platform/scripts/` (`deploy.sh`, `status.sh`, `stop.sh`)
- `platform/.env.example` for documented future environment variables

## Platform milestones

### Nginx reverse proxy

- Added Nginx as the public entry point on port 80
- Browser traffic flows: Nginx → Open WebUI → Ollama
- Compose stack: `ai-security-platform` (Ollama, Open WebUI, Nginx)

### AI platform blueprint

- Added `platform/docs/platform-blueprint.md` with full platform vision, security model, traffic flows, and roadmap

### AI platform infrastructure

- Docker Compose deployment on hardened Ubuntu VPS
- Ollama LLM service with persistent model storage
- Open WebUI browser interface
- External Docker volumes for Ollama and Open WebUI data

### Platform architecture documentation

- Added `platform/docs/architecture.md` and `platform/docs/lab-notes.md`
- Documented deployment status and operational checklist

## MCP investigation and reporting (v1.x)

### v1.3 — Markdown incident report export

- Export structured incident reports as Markdown

### v1.2 — Analyst QA and Splunk integration

- Analyst decision review and investigation QA workflows
- Splunk SPL generation for detection and investigation queries

### v1.1 — Incident reporting and enrichment

- Incident reporting and observable enrichment workflows
- Incident report generation workflows

### v1.0 — SOC investigation core

- Security copilot investigation chains
- Multi-alert correlation and attack chain analysis
- AI-assisted investigation runbook generation
- Linux auth telemetry analysis workflows
- Detection engineering (Sigma, Sentinel, Defender, QRadar)
- Custom Python MCP server (`scripts/soc_mcp_server.py`) for structured SOC workflows
