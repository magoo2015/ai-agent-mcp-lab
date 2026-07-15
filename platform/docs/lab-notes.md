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
- Core platform deployed (Open WebUI, Nginx, observability) — default `deploy.sh`
- Ollama and AI Gateway optional via Docker Compose **`ai` profile** (`start-ai.sh`)
- gemma2:2b model installed and tested (when AI profile is running)
- tinyllama model installed (default fast test model for AI Gateway)
- Observability stack deployed (Prometheus, Grafana, Node Exporter, cAdvisor)
- HTTPS/TLS Hardening v1 bootstrap prepared (domain, certificate issuance, and HTTPS activation still pending)

## Core vs AI profile

| Profile | Services |
| ------- | -------- |
| **(default)** | nginx, open-webui, prometheus, grafana, node-exporter, cadvisor |
| **`ai`** | ollama, ai-gateway |

On a **2 vCPU / 4GB** VPS, start inference only when needed:

```bash
./platform/scripts/start-ai.sh
# or: docker compose --profile ai up -d
```

Stop inference without stopping observability:

```bash
./platform/scripts/stop-ai.sh
```

Ollama is optional because local LLM inference is heavy on CPU and RAM. Running it continuously on a small VPS can slow SSH, Grafana, and other services. **tinyllama** is the default fast test model; **gemma2:2b** is optional and slower on CPU-only hosts.

## Architecture

MacBook connects to the VPS over SSH.

The VPS runs Docker containers for AI services and observability.

Current containers:

**Core (always on after `deploy.sh`):**

- Open WebUI (internal)
- Nginx (sole public application entry point; HTTP bootstrap on port 80, port 443 reserved)
- Prometheus (internal — metrics TSDB)
- Node Exporter (internal — host metrics)
- cAdvisor (internal — container metrics)
- Grafana (internal; authenticated `/grafana/` route through Nginx)

**AI profile (`start-ai.sh`):**

- Ollama (internal)
- AI Gateway (internal; `/gateway/` via Nginx — returns 502 when stopped)

### AI traffic flow

```text
Browser → Nginx :80 / → Open WebUI :8080 → Ollama :11434 → tinyllama / gemma2:2b
Client  → Nginx :80 /gateway/ → AI Gateway :8000 → Ollama :11434 → tinyllama (default) / gemma2:2b
```

These are bootstrap HTTP paths. A trusted certificate and HTTPS redirect are not active yet.

### AI Gateway quick test

Requires the `ai` profile: `./platform/scripts/start-ai.sh`

```bash
# Health check
curl -s http://localhost/gateway/health

# List models
curl -s http://localhost/gateway/models

# Chat (non-streaming; tinyllama is the default)
curl -s http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-local-gateway-key>" \
  -d '{"prompt": "Say hello in one sentence."}'

# Chat with gemma2:2b (slower on this VPS)
curl -s http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-local-gateway-key>" \
  -d '{"model": "gemma2:2b", "prompt": "Say hello in one sentence."}'
```

### Observability flow

```text
Browser → Nginx :80 /grafana/ → Grafana :3000 (internal)
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
| **Grafana** | Authenticated dashboard UI behind Nginx at `http://<vps-ip>/grafana/` during bootstrap. Anonymous access and self-signup are disabled. Data volume: `grafana`. |

### First-time Grafana setup

1. Open `http://<vps-ip>/grafana/` and log in with the administrator credentials configured for this deployment.
2. Add Prometheus as a data source: **Connections → Data sources → Add → Prometheus**.
3. Set URL to `http://prometheus:9090` (Docker service name on the compose network).
4. Save & test, then explore metrics or import a community dashboard (e.g. Node Exporter Full, Docker cAdvisor).

Do not open port 3001. Grafana has no host port mapping. For the future HTTPS endpoint, verify only TCP 80 and 443 in both UFW and the DigitalOcean Cloud Firewall; SSH remains host-managed separately.

## Next Goals

- Configure a real public hostname and complete the staged TLS issuance/activation runbook in [tls.md](./tls.md)
- Pre-built Grafana dashboards and basic alerting
- Add promptfoo (via AI Gateway)
- Add garak (via AI Gateway)
- Integrate AI Agent MCP Lab
