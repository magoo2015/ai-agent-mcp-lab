# AI Security Platform Lab Notes

See also: [platform-blueprint.md](./platform-blueprint.md) for the full platform vision, security model, and roadmap.

## Current Status

- DigitalOcean Ubuntu VPS created
- SSH key authentication configured
- Non-root admin user created: sysadmin
- UFW firewall enabled
- Fail2ban enabled
- Root SSH login disabled
- Docker and Docker Compose installed
- Ollama deployed with Docker Compose
- Open WebUI deployed with Docker Compose
- Nginx reverse proxy deployed (port 80)
- gemma2:2b model installed and tested
- Observability stack deployed (Prometheus, Grafana, Node Exporter, cAdvisor)

## Architecture

MacBook connects to the VPS over SSH.

The VPS runs Docker containers for AI services and observability.

Current containers:

- Ollama (internal)
- Open WebUI (internal)
- Nginx (public entry point on port 80)
- Prometheus (internal — metrics TSDB)
- Node Exporter (internal — host metrics)
- cAdvisor (internal — container metrics)
- Grafana (public dashboards on port 3001)

### AI traffic flow

```text
Browser → Nginx :80 → Open WebUI :8080 → Ollama :11434 → gemma2:2b
```

### Observability flow

```text
Browser → Grafana :3001
              ↓ PromQL
         Prometheus
              ↑ scrape (15s)
    Node Exporter | cAdvisor | Prometheus (self)
```

## Observability components

| Component | Role |
| --------- | ---- |
| **Prometheus** | Scrapes metric endpoints and stores time-series data. Config: `platform/prometheus/prometheus.yml`. Data volume: `prometheus`. |
| **Node Exporter** | Exposes VPS host metrics (CPU, memory, disk, network) for Prometheus. |
| **cAdvisor** | Exposes per-container CPU, memory, and I/O metrics for Prometheus. |
| **Grafana** | Web UI for dashboards. Default login on first visit: `admin` / `admin` (change immediately). Data volume: `grafana`. URL: `http://<vps-ip>:3001`. |

### First-time Grafana setup

1. Open `http://<vps-ip>:3001` and log in (default `admin` / `admin`).
2. Add Prometheus as a data source: **Connections → Data sources → Add → Prometheus**.
3. Set URL to `http://prometheus:9090` (Docker service name on the compose network).
4. Save & test, then explore metrics or import a community dashboard (e.g. Node Exporter Full, Docker cAdvisor).

Ensure UFW allows port 3001 if accessing Grafana from outside the VPS:

```bash
sudo ufw allow 3001/tcp
```

## Next Goals

- Add HTTPS/TLS (terminate at Nginx; planned for a later module)
- Pre-built Grafana dashboards and basic alerting
- Add promptfoo
- Add garak
- Integrate AI Agent MCP Lab
