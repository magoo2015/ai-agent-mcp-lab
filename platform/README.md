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
- **Observability stack** — Prometheus, Grafana, Node Exporter, and cAdvisor

## Current Architecture

```text
Browser → Nginx :80 → Open WebUI :8080 → Ollama :11434 → gemma2:2b

Grafana :3001 → dashboards (Prometheus datasource)
Prometheus ← scrapes ← Node Exporter (host metrics)
                      ← cAdvisor (container metrics)
                      ← Prometheus (self-monitoring)

Developer workstation → Cursor + MCP → soc-assistant → structured security workflows
```

## Observability Stack

| Component | Role |
| --------- | ---- |
| **Prometheus** | Time-series metrics database. Scrapes exporters on a schedule and stores samples for querying and alerting. |
| **Node Exporter** | Exposes host-level metrics (CPU, memory, disk, network) from the VPS for Prometheus to collect. |
| **cAdvisor** | Exposes per-container resource usage (CPU, memory, filesystem) from Docker for Prometheus to collect. |
| **Grafana** | Visualization layer. Connects to Prometheus and renders dashboards for platform health and capacity. |

Grafana is published on host port **3001** (`http://<vps-ip>:3001`). Prometheus, Node Exporter, and cAdvisor stay on the internal Docker network.

Configuration:

- `prometheus/prometheus.yml` — scrape targets and intervals
- `grafana/` — directory reserved for future Grafana provisioning (dashboards, datasources)
- Docker volumes `prometheus` and `grafana` persist metrics TSDB data and Grafana state

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
| [docs/observability.md](docs/observability.md) | Prometheus, Grafana, exporters, dashboards, and troubleshooting |
| [docs/lab-notes.md](docs/lab-notes.md) | Deployment status and operational checklist |

## Platform Goals

- Add HTTPS/TLS (planned for a later module; Nginx is in place as the entry point)
- Expand Grafana dashboards and basic alerting (disk, container down, high load)
- Add promptfoo for AI prompt evaluation
- Add garak for AI security testing
- Add GitHub Actions for CI
- Integrate with the MCP security assistant
