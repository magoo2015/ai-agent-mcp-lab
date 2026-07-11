# AI Security Platform Architecture

> For the complete platform blueprint—including security model, roadmap, and interview narrative—see [platform-blueprint.md](./platform-blueprint.md).

## Overview

The AI Security Engineering Platform runs on a DigitalOcean Ubuntu VPS and provides self-hosted AI services for security investigation, AI prompt testing, model evaluation, and MCP-integrated SOC workflows. The application-layer MCP server (`soc-assistant`) runs on the developer workstation; the VPS hosts the containerized LLM stack and an observability layer for host and container metrics.

## Current Components

### DigitalOcean VPS

The VPS provides the Linux runtime environment for Docker, AI tooling, monitoring, and security platform services.

### Docker

Docker is used to containerize platform services so they can be managed consistently with Docker Compose.

### Ollama

Ollama runs the local language model backend. It is part of the Docker Compose **`ai` profile** and does not start with the default deploy — see [README](../README.md#core-platform-vs-ai-profile).

On a 2 vCPU / 4GB VPS, keeping Ollama stopped until needed avoids overloading the host with inference workloads alongside monitoring and the web UI.

Installed models (when the `ai` profile is running):

- **tinyllama** — default for AI Gateway `/chat` when no `model` is specified (`DEFAULT_MODEL=tinyllama`). Fast on the current 2 vCPU / 4GB VPS.
- **gemma2:2b** — optional; higher quality but slower on CPU-only hosts. Pass `"model": "gemma2:2b"` to override the default.

Larger models need more CPU, RAM, and ideally a GPU. Use small models on constrained VPS instances unless you scale up the host.

### Open WebUI

Open WebUI provides a browser-based chat interface connected to Ollama. It is reachable only on the internal Docker network; users access it through Nginx at `/`. It starts with the **core** profile; chat requires Ollama (`docker compose --profile ai up -d` or `./scripts/start-ai.sh`).

### AI Gateway

A lightweight FastAPI service (`platform/ai-gateway/`) that routes requests to Ollama or OpenAI. It is **internal-only** on the Docker network (no host port **8000** published). External access is only through Nginx at `/gateway/`. Part of the **`ai` profile**. If ai-gateway is not running, Nginx still serves `/gateway/` but returns **502 Bad Gateway**.

Endpoints:

- `GET /health` — service status (unauthenticated; safe for ops probes)
- `GET /metrics` — Prometheus scrape target (**internal only**; not proxied by Nginx)
- `GET /models` — available models (Ollama `/api/tags`)
- `POST /chat` — non-streaming generation; requires `X-API-Key`; prompt/body size limited

Hardening v1 adds a shared gateway API key, request-size limits, and removal of direct host exposure. Traffic is still **HTTP** (TLS is a later phase). See [ai-gateway.md](./ai-gateway.md).

### Nginx

Nginx acts as the reverse proxy and **sole public entry point** for the AI chat stack and gateway API. It listens on port 80 and forwards `/` to Open WebUI and `/gateway/` to the AI Gateway on the Docker network. The `/gateway/` location forwards `X-API-Key` and sets `client_max_body_size 64k`. Nginx does **not** expose `/metrics`. Nginx depends only on Open WebUI at startup so the core stack can run without the `ai` profile.

### Observability

| Service | Purpose |
| ------- | ------- |
| **Prometheus** | Pull-based metrics collection and time-series storage. Scrapes Node Exporter, cAdvisor, and itself on a 15-second interval (`prometheus/prometheus.yml`). Data persists in the `prometheus` Docker volume. |
| **Node Exporter** | Host metrics exporter. Publishes CPU, memory, disk, and network statistics from the VPS kernel and filesystems for Prometheus to scrape. |
| **cAdvisor** | Container metrics exporter. Reads Docker cgroup and container runtime data to expose per-container CPU, memory, and I/O usage. |
| **Grafana** | Dashboard and exploration UI. Operators connect Grafana to Prometheus to visualize platform health. Published on host port **3001**; dashboard and user data persist in the `grafana` Docker volume. |

Prometheus, Node Exporter, and cAdvisor are not published on host ports—they communicate only on the Docker network. Grafana is the operator-facing entry point for metrics visualization.

### Volumes

Docker volumes persist model files, Open WebUI data, Prometheus TSDB data, and Grafana configuration/dashboard state across container restarts.

### MCP Lab

The repository root contains `scripts/soc_mcp_server.py`, a Python FastMCP server that exposes SOC investigation tools to AI agents (Cursor and other MCP clients). It complements the VPS-hosted chat stack by providing structured, bounded security automation—not additional containers on the VPS today.

## Architecture Diagram

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│  DigitalOcean VPS — Ubuntu                                                  │
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐ │
│  │ Nginx :80    │────▶│ Open WebUI   │────▶│ Ollama       │────▶│ tinyllama│ │
│  │ (public)     │     │ :8080 int.   │     │ :11434 int.  │     │ gemma2:2b│ │
│  └──────┬───────┘     └──────────────┘     └──────────────┘     └──────────┘ │
│         │                                                                   │
│         │ /gateway/  (X-API-Key for /chat)                                  │
│         ▼                                                                   │
│  ┌────────────────┐   scrape /metrics (Docker net)   ┌─────────────┐       │
│  │ AI Gateway     │◀─────────────────────────────────│ Prometheus  │       │
│  │ :8000 internal │─────────────────────────────────▶│ (TSDB)      │       │
│  │ (no host :8000)│──────────────▶ Ollama            └─────────────┘       │
│  └────────────────┘                                                         │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ Observability (internal scrape path)                                  │  │
│  │                                                                       │  │
│  │  ┌─────────────┐   scrape    ┌──────────────┐   ┌─────────────────┐  │  │
│  │  │ Prometheus  │◀────────────│ Node Exporter│   │ cAdvisor        │  │  │
│  │  │ (TSDB)      │◀────────────│ (host metrics)│   │ (container metrics)│  │  │
│  │  └──────┬──────┘             └──────────────┘   └─────────────────┘  │  │
│  │         │ query                                                       │  │
│  │         ▼                                                             │  │
│  │  ┌─────────────┐                                                      │  │
│  │  │ Grafana     │  :3001 (public — dashboards)                         │  │
│  │  └─────────────┘                                                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Current Traffic Flow

### AI chat path (Open WebUI)

```text
User Browser
    ↓
Nginx :80 /
    ↓
Open WebUI :8080 (internal)
    ↓
Ollama :11434 (internal)
    ↓
tinyllama / gemma2:2b (user-selected in Open WebUI)
```

### AI Gateway path

```text
Client (curl, automation)
    ↓  X-API-Key required for POST /chat
Nginx :80 /gateway/
    ↓
AI Gateway :8000 (Docker network only — host port 8000 not published)
    ↓
Ollama :11434 (internal)  or  OpenAI (HTTPS)
    ↓
tinyllama (default) or explicit model override
```

`GET /health` remains unauthenticated for liveness. `GET /metrics` is scraped by Prometheus at `http://ai-gateway:8000/metrics` and is **not** available through Nginx.

### Observability path

```text
Operator Browser
    ↓
Grafana :3001
    ↓  (PromQL queries)
Prometheus (internal)
    ↑  scrape (every 15s)
    ├── Node Exporter :9100 (host CPU, memory, disk, network)
    ├── cAdvisor :8080 (per-container resource usage)
    └── Prometheus :9090 (self-monitoring)
```

Ollama, Open WebUI, and the AI Gateway are not published on public host ports. Nginx exposes port 80 for the chat UI and gateway API; Grafana exposes port 3001 for metrics dashboards. Gateway `/metrics` stays on the internal Docker network for Prometheus only.
