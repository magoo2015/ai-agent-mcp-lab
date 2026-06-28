# AI Security Engineering Platform

This directory contains the **infrastructure layer** for the [AI Agent MCP Lab](../README.md): a self-hosted AI runtime on a hardened VPS, paired with a custom MCP security assistant in the repository root.

For the full platform vision, security model, traffic flows, and interview-ready narrative, see **[docs/platform-blueprint.md](docs/platform-blueprint.md)**.

## Current Capabilities

- Self-hosted Ollama LLM service
- Open WebUI browser interface
- Docker Compose deployment
- Persistent Docker volumes for model and application data
- DigitalOcean Ubuntu VPS deployment
- MCP lab (`scripts/soc_mcp_server.py`) — SOC investigation tools for AI agents

## Current Architecture

Browser → Open WebUI → Ollama → Local model

Developer workstation → Cursor + MCP → soc-assistant → structured security workflows

## Current Model

- gemma2:2b

## Documentation

| Document | Purpose |
| -------- | ------- |
| [docs/platform-blueprint.md](docs/platform-blueprint.md) | Full platform blueprint (architecture, security, roadmap) |
| [docs/architecture.md](docs/architecture.md) | Current component and traffic-flow summary |
| [docs/lab-notes.md](docs/lab-notes.md) | Deployment status and operational checklist |

## Platform Goals

- Add Nginx reverse proxy
- Add HTTPS/TLS
- Add Prometheus and Grafana monitoring
- Add promptfoo for AI prompt evaluation
- Add garak for AI security testing
- Add GitHub Actions for CI
- Integrate with the MCP security assistant
