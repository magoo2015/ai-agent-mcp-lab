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

Ollama runs the local language model backend.

Current model:

- gemma2:2b

### Open WebUI

Open WebUI provides a browser-based chat interface connected to Ollama. It is reachable only on the internal Docker network; users access it through Nginx.

### Nginx

Nginx acts as the reverse proxy and single public entry point for the AI chat stack. It listens on port 80 and forwards traffic to Open WebUI on the Docker network.

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
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌────────┐ │
│  │ Nginx :80    │────▶│ Open WebUI   │────▶│ Ollama       │────▶│ gemma2 │ │
│  │ (public)     │     │ :8080 int.   │     │ :11434 int.  │     │ :2b    │ │
│  └──────────────┘     └──────────────┘     └──────────────┘     └────────┘ │
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

### AI chat path

```text
User Browser
    ↓
Nginx :80
    ↓
Open WebUI :8080 (internal)
    ↓
Ollama :11434 (internal)
    ↓
gemma2:2b
```

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

Ollama and Open WebUI are not published on public host ports. Nginx exposes port 80 for the chat UI; Grafana exposes port 3001 for metrics dashboards.
