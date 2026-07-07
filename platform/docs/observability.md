# Observability

This document describes the monitoring stack for the AI Security Engineering Platform: what each component does, how to access Grafana, how to wire Prometheus as a data source, and how to troubleshoot common issues.

For architecture context, see [architecture.md](./architecture.md). For deployment and day-to-day operations, see [../README.md](../README.md).

## Why Observability Matters

For AI, SRE, and security engineering workloads, you cannot rely on "it feels slow" or ad-hoc `docker logs` checks alone.

- **AI runtime health** — LLM inference (Ollama) and the chat UI (Open WebUI) are resource-intensive. CPU, memory, and disk pressure directly affect model load times, token throughput, and user experience. Metrics make capacity limits visible before users hit them.
- **SRE practices** — Prometheus provides a consistent, queryable history of host and container metrics. That supports incident response ("when did memory spike?"), capacity planning, and future alerting on signals like disk full, container down, or sustained high load.
- **Security engineering** — A self-hosted platform on a VPS is part of your attack surface. Observability helps detect anomalous resource use (crypto miners, runaway containers), verify that only expected services are running, and correlate infrastructure events with application or proxy behavior during investigations.

The stack follows a standard pattern: **exporters expose metrics → Prometheus scrapes and stores them → Grafana visualizes them**.

## Components

### Prometheus

**Purpose:** Time-series metrics database and scraper.

Prometheus pulls metrics from configured targets on a schedule (15-second interval in `prometheus/prometheus.yml`), stores samples in its TSDB, and exposes a query API (PromQL). It scrapes:

- Itself (`localhost:9090` inside the container)
- Node Exporter (`node-exporter:9100`)
- cAdvisor (`cadvisor:8080`)
- AI Gateway (`ai-gateway:8000`) — application metrics for `/chat` requests

Prometheus runs on the internal Docker network only—it is **not** published on a host port. Other containers (including Grafana) reach it at `http://prometheus:9090`.

Configuration: [`prometheus/prometheus.yml`](../prometheus/prometheus.yml). Metrics data persists in the `prometheus` Docker volume.

### Grafana

**Purpose:** Visualization and exploration UI.

Grafana connects to Prometheus (and other data sources) and renders dashboards, graphs, and ad-hoc queries. It is the operator-facing entry point for platform health and capacity.

Grafana is published on host port **3001** (mapped to container port 3000). Dashboard and user settings persist in the `grafana` Docker volume.

### Node Exporter

**Purpose:** Host-level metrics exporter.

Node Exporter reads the VPS kernel and filesystems (`/proc`, `/sys`, root filesystem) and exposes standard host metrics: CPU, memory, disk space and I/O, network interfaces, and load. Prometheus scrapes these to monitor the machine running Docker, Ollama, and the rest of the stack.

Node Exporter is internal-only; it is not exposed on a host port.

### cAdvisor

**Purpose:** Container-level metrics exporter.

cAdvisor inspects Docker cgroups and container runtime state to expose per-container CPU, memory, filesystem, and network usage. Use it to see which services (Ollama, Open WebUI, Nginx, Prometheus, etc.) consume resources and to spot leaks or runaway processes.

cAdvisor is internal-only; it is not exposed on a host port.

### AI Gateway metrics

**Purpose:** Application-level metrics for LLM routing through the gateway.

The AI Gateway exposes `GET /metrics` in Prometheus text format. Each `/chat` request increments counters and observes latency histograms with **low-cardinality labels only** (`provider`, `model`, `status`, `error_type`). Prompts, `request_id`, client IPs, and API keys are never included in metric labels.

| Metric | Type | Labels |
| ------ | ---- | ------ |
| `ai_gateway_requests_total` | Counter | `provider`, `model`, `status` |
| `ai_gateway_request_latency_seconds` | Histogram | `provider`, `model` |
| `ai_gateway_errors_total` | Counter | `provider`, `model`, `error_type` |

Scrape job: `ai-gateway` → `ai-gateway:8000` in [`prometheus/prometheus.yml`](../prometheus/prometheus.yml).

**Example PromQL queries:**

```promql
# Request rate by provider (5m window)
sum by (provider) (rate(ai_gateway_requests_total[5m]))

# p95 latency by provider
histogram_quantile(0.95, sum by (provider, le) (rate(ai_gateway_request_latency_seconds_bucket[5m])))

# Error rate by type
sum by (error_type) (rate(ai_gateway_errors_total[5m]))
```

See [ai-gateway.md](./ai-gateway.md#prometheus-metrics) for label rationale, security tradeoffs, and why prompts are excluded from metrics.

## Access Grafana

1. Ensure the stack is running from `platform/`:

   ```bash
   docker compose ps
   ```

2. Open Grafana in a browser:

   ```text
   http://<vps-ip>:3001
   ```

   Replace `<vps-ip>` with your VPS public IP or use `http://localhost:3001` when working on the server directly.

3. Log in with the default Grafana credentials (change these after first login in production):

   - Username: `admin`
   - Password: `admin`

## Add Prometheus as a Grafana Data Source

Because Prometheus is on the Docker network, use the **internal** service hostname—not `localhost`—from inside Grafana:

1. In Grafana, go to **Connections → Data sources** (or **Configuration → Data sources** in older UI).
2. Click **Add data source**.
3. Select **Prometheus**.
4. Set **URL** to:

   ```text
   http://prometheus:9090
   ```

5. Leave other settings at defaults unless you have a specific need.
6. Click **Save & test**. You should see **Successfully queried the Prometheus API**.

`localhost:9090` from inside the Grafana container would point at Grafana itself, not Prometheus—always use `http://prometheus:9090`.

## Recommended Dashboards

Import community dashboards from [grafana.com/grafana/dashboards](https://grafana.com/grafana/dashboards/) via **Dashboards → New → Import** and enter the dashboard ID.

| Dashboard | Grafana.com ID | Use for |
| --------- | -------------- | ------- |
| **Node Exporter Full** | [1860](https://grafana.com/grafana/dashboards/1860) | Host CPU, memory, disk, network, and load on the VPS |
| **Docker / cAdvisor** | [14282](https://grafana.com/grafana/dashboards/14282) (or search "cAdvisor") | Per-container CPU, memory, and I/O for Docker services |
| **AI Gateway (custom)** | Build your own | Request rate, error rate, and latency percentiles from `ai_gateway_*` metrics |

When importing, select your Prometheus data source. Adjust panel time ranges and refresh intervals (e.g. 30s or 1m) for live operations.

For the AI Gateway, create panels using the PromQL examples in [AI Gateway metrics](#ai-gateway-metrics) above — e.g. `rate(ai_gateway_requests_total[5m])` and `histogram_quantile(0.95, ...)`.

## Useful Commands

Run these from the `platform/` directory unless noted.

**Service status (all containers):**

```bash
docker compose ps
```

**Platform status script (compose ps, recent app logs, Nginx health check):**

```bash
./scripts/status.sh
```

**Prometheus logs (last 50 lines):**

```bash
docker logs prometheus --tail 50
```

**Grafana logs (last 50 lines):**

```bash
docker logs grafana --tail 50
```

**AI Gateway metrics (direct from gateway host port):**

```bash
curl -s http://localhost:8000/metrics | grep ai_gateway
```

**Prometheus targets (from inside the Prometheus container):**

```bash
docker exec prometheus wget -qO- http://localhost:9090/api/v1/targets | grep ai-gateway
```

**All observability service logs:**

```bash
docker compose logs --tail=50 prometheus grafana node-exporter cadvisor
```

## Troubleshooting

### Grafana works but shows no data

1. **Confirm Prometheus is scraping targets** — From a container on the same network, or by inspecting Prometheus logs:

   ```bash
   docker logs prometheus --tail 50
   ```

   Look for scrape errors or "connection refused" messages.

2. **Verify the Grafana data source URL** — It must be `http://prometheus:9090`, not `http://localhost:9090`.

3. **Check time range** — Grafana defaults to "Last 6 hours". If the stack was just started, narrow to "Last 15 minutes" or use **Refresh**.

4. **Confirm exporters are up:**

   ```bash
   docker compose ps node-exporter cadvisor prometheus
   ```

5. **Test a simple query in Grafana** — Explore → Prometheus → run `up`. Values of `1` mean the target is reachable; `0` means scrape failure.

### Prometheus not reachable from the host

This is **expected**. Prometheus is intentionally internal-only (no `ports:` mapping in `docker-compose.yml`). It is reachable as:

- `http://prometheus:9090` from other containers (Grafana, etc.)
- Not from your laptop browser unless you add a port mapping or SSH tunnel

To debug Prometheus from the VPS host without exposing it publicly:

```bash
docker exec -it prometheus wget -qO- http://localhost:9090/-/healthy
```

Or use Grafana's data source test and Explore UI as the supported operator path.

### Open WebUI behind Nginx

The chat UI is **not** directly exposed on a host port. Traffic flow:

```text
Browser → Nginx :80 → Open WebUI :8080 (internal) → Ollama :11434 (internal)
```

- Use `http://<vps-ip>` or `http://localhost` for the Web UI, not Open WebUI's internal port.
- If the UI is down but Grafana looks healthy, check Nginx and app containers:

  ```bash
  ./scripts/status.sh
  docker compose logs --tail=50 nginx open-webui ollama
  ```

- Observability metrics for Nginx/Open WebUI/Ollama appear under **cAdvisor / Docker** dashboards (container CPU and memory), not as separate Prometheus jobs unless you add exporters later.

## Related Configuration

| Path | Role |
| ---- | ---- |
| [`docker-compose.yml`](../docker-compose.yml) | Service definitions; Grafana `3001:3000` |
| [`prometheus/prometheus.yml`](../prometheus/prometheus.yml) | Scrape targets and intervals |
| [`scripts/status.sh`](../scripts/status.sh) | Quick health check for the application stack |

## Next Steps

- Change default Grafana credentials after first login.
- Import the recommended dashboards and bookmark them for incident response.
- Plan alerting (disk space, `up == 0`, high CPU) as a follow-on module—Prometheus is already collecting the underlying series.
