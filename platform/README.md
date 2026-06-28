# AI Security Engineering Platform

This directory contains the **infrastructure layer** for the [AI Agent MCP Lab](../README.md): a self-hosted AI runtime on a hardened VPS, paired with a custom MCP security assistant in the repository root.

For the full platform vision, security model, traffic flows, and interview-ready narrative, see **[docs/platform-blueprint.md](docs/platform-blueprint.md)**.

## Current Capabilities

- Self-hosted Ollama LLM service
- Open WebUI browser interface
- Nginx reverse proxy (port 80)
- Docker Compose deployment
- Persistent Docker volumes for model and application data
- DigitalOcean Ubuntu VPS deployment
- MCP lab (`scripts/soc_mcp_server.py`) — SOC investigation tools for AI agents

## Current Architecture

Browser → Nginx :80 → Open WebUI :8080 → Ollama :11434 → gemma2:2b

Developer workstation → Cursor + MCP → soc-assistant → structured security workflows

## Current Model

- gemma2:2b

## Helper Scripts

Operational scripts live in [`scripts/`](scripts/). Run them from anywhere; each script resolves `platform/` automatically.

| Script | Purpose |
| ------ | ------- |
| [`scripts/deploy.sh`](scripts/deploy.sh) | Verify Docker/Compose, validate config, start the stack |
| [`scripts/status.sh`](scripts/status.sh) | Show service status, recent logs, and Nginx health check |
| [`scripts/stop.sh`](scripts/stop.sh) | Stop containers (`docker compose down`; volumes preserved) |

```bash
./platform/scripts/deploy.sh
./platform/scripts/status.sh
./platform/scripts/stop.sh
```

Optional environment overrides: copy [`.env.example`](.env.example) to `.env` in this directory.

## Documentation

| Document | Purpose |
| -------- | ------- |
| [docs/platform-blueprint.md](docs/platform-blueprint.md) | Full platform blueprint (architecture, security, roadmap) |
| [docs/architecture.md](docs/architecture.md) | Current component and traffic-flow summary |
| [docs/lab-notes.md](docs/lab-notes.md) | Deployment status and operational checklist |

## Platform Goals

- Add HTTPS/TLS (planned for a later module; Nginx is in place as the entry point)
- Add Prometheus and Grafana monitoring
- Add promptfoo for AI prompt evaluation
- Add garak for AI security testing
- Add GitHub Actions for CI
- Integrate with the MCP security assistant
