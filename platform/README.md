# AI Security Engineering Platform

This directory contains the **infrastructure layer** for the [AI Agent MCP Lab](../README.md): a self-hosted AI runtime on a hardened VPS, paired with a custom MCP security assistant in the repository root.

For the full platform vision, security model, traffic flows, and interview-ready narrative, see **[docs/platform-blueprint.md](docs/platform-blueprint.md)**.

## Current Capabilities

- Self-hosted Ollama LLM service (optional — Docker Compose `ai` profile)
- Open WebUI browser interface
- **AI Gateway** — FastAPI proxy to Ollama (`/gateway/` via Nginx; optional `ai` profile)
- Nginx reverse proxy (port 80)
- Docker Compose deployment with **core** and **AI** profiles
- Persistent Docker volumes for model and application data
- DigitalOcean Ubuntu VPS deployment
- MCP lab (`scripts/soc_mcp_server.py`) — SOC investigation tools for AI agents
- **Observability stack** — Prometheus, Grafana, Node Exporter, and cAdvisor

## Core Platform vs AI Profile

On a **2 vCPU / 4GB RAM** VPS, Ollama and the AI Gateway can overload the host if they start with every deploy. The stack is split so the **core platform** stays light by default:

| Profile | Services | When to use |
| ------- | -------- | ----------- |
| **(default)** | nginx, open-webui, prometheus, grafana, node-exporter, cadvisor | Day-to-day UI and observability |
| **`ai`** | ollama, ai-gateway | When you need local inference or `/gateway/` API access |

Deploy core only (default):

```bash
./platform/scripts/deploy.sh
```

Start AI inference when needed:

```bash
./platform/scripts/start-ai.sh
# or: docker compose --profile ai up -d
```

Stop AI without touching the core stack:

```bash
./platform/scripts/stop-ai.sh
```

Open WebUI and Nginx start with the core profile. Chat requires Ollama (`start-ai.sh`). The `/gateway/` route stays in the Nginx config; if ai-gateway is stopped, requests to `/gateway/` return **502 Bad Gateway**.

**Why Ollama is optional:** LLM inference is CPU- and memory-intensive. On a small VPS, running Ollama continuously alongside monitoring and the web UI can cause swap thrashing, slow SSH, and failed health checks. Start the `ai` profile only when you are actively testing or chatting.

## Current Architecture

```text
Browser → Nginx :80 → Open WebUI :8080 → Ollama :11434 → tinyllama (default) / gemma2:2b
Browser → Nginx :80/gateway/ → AI Gateway :8000 → Ollama :11434

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

Grafana is published on host port **3001** (`http://<vps-ip>:3001`). Prometheus, Node Exporter, cAdvisor, and the AI Gateway stay on the internal Docker network.

## AI Gateway

Lightweight FastAPI service at `platform/ai-gateway/`. Proxies requests to Ollama and provides a foundation for future model routing, logging, promptfoo/garak testing, and MCP integration.

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/health` | GET | Service status |
| `/models` | GET | Lists models from Ollama `/api/tags` |
| `/chat` | POST | Generate a response (`prompt` required; `model` optional) |

Access via Nginx at `http://<vps-ip>/gateway/` (e.g. `http://<vps-ip>/gateway/health`). The gateway container is not published on a host port.

Example chat request (uses `tinyllama` by default):

```bash
curl -s http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello"}'
```

Override the model explicitly:

```bash
curl -s http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -d '{"model": "gemma2:2b", "prompt": "Hello"}'
```

Responses include `model_used` so callers can see which model handled the request.

Configuration:

- `prometheus/prometheus.yml` — scrape targets and intervals
- `grafana/` — directory reserved for future Grafana provisioning (dashboards, datasources)
- Docker volumes `prometheus` and `grafana` persist metrics TSDB data and Grafana state

## Current Models

Models are available only when the **`ai` profile** is running (`./scripts/start-ai.sh`).

- **tinyllama** — default for the AI Gateway (`DEFAULT_MODEL=tinyllama`). Fast on the current 2 vCPU / 4GB VPS; good for quick tests and automation.
- **gemma2:2b** — optional; install via Open WebUI or pass `"model": "gemma2:2b"` to `/gateway/chat`. Higher quality but noticeably slower on this VPS without GPU acceleration.

Larger models require more CPU, RAM, and ideally a GPU. Stay with small models on constrained hosts unless you scale the instance or add dedicated inference hardware.

## Helper Scripts

Operational scripts live in [`scripts/`](scripts/). Run them from anywhere; each script resolves `platform/` automatically.

| Script | Purpose |
| ------ | ------- |
| [`scripts/deploy.sh`](scripts/deploy.sh) | Verify Docker/Compose, validate config, start the **core** stack |
| [`scripts/start-ai.sh`](scripts/start-ai.sh) | Start Ollama and AI Gateway (`ai` profile) |
| [`scripts/stop-ai.sh`](scripts/stop-ai.sh) | Stop Ollama and AI Gateway; core platform keeps running |
| [`scripts/status.sh`](scripts/status.sh) | Show service status, recent logs, and Nginx health check |
| [`scripts/stop.sh`](scripts/stop.sh) | Stop containers (`docker compose down`; volumes preserved) |

```bash
./platform/scripts/deploy.sh
./platform/scripts/start-ai.sh    # optional — when you need inference
./platform/scripts/stop-ai.sh     # free RAM without stopping observability
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
- Add promptfoo for AI prompt evaluation (via AI Gateway)
- Add garak for AI security testing (via AI Gateway)
- Add GitHub Actions for CI
- Integrate with the MCP security assistant
