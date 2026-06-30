# AI Security Engineering Platform — Blueprint

A portfolio-grade reference for the infrastructure and application layers that power the **AI Agent MCP Lab**. This document describes what the platform is today, how traffic and trust boundaries are designed, and where the project is headed.

---

## Project Purpose

The AI Security Engineering Platform combines two complementary layers:

1. **Self-hosted AI runtime** — A DigitalOcean VPS running containerized LLM services for local inference, experimentation, and future security testing workflows.
2. **MCP security lab** — A custom Python MCP server (`soc-assistant`) that exposes structured SOC investigation tools to AI agents in Cursor and other MCP-compatible clients.

The goal is not to ship a commercial product. The goal is to demonstrate **responsible AI security engineering**: how to host models safely, how to give agents bounded tools instead of open-ended shell access, and how to automate repeatable security workflows (alert triage, correlation, detection engineering, incident reporting) in a lab environment.

This project is suitable as a GitHub portfolio piece for roles in:

- AI security engineering
- Security automation and detection engineering
- SOC tooling and workflow design
- Platform engineering with a security focus

---

## Current Architecture

At a high level, development happens on a local workstation while the AI runtime runs on a remote VPS. The MCP lab runs where the developer works (typically via Cursor) and calls Python tools that operate on local sample data and optional lab telemetry.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  Developer Workstation (e.g. MacBook)                                   │
│  ┌──────────────────┐    ┌──────────────────────────────────────────┐ │
│  │ Cursor + MCP     │───▶│ soc-assistant MCP server (Python)        │ │
│  │ (soc-assistant)  │    │ Alert triage, correlation, reporting   │ │
│  └──────────────────┘    └──────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ SSH (admin access)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DigitalOcean VPS — Ubuntu                                            │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐ │
│  │ Docker      │───▶│ Nginx        │───▶│ Open WebUI   │───▶│ Ollama  │ │
│  │ Compose     │    │ :80          │    │ :8080        │    │ gemma2  │ │
│  └─────────────┘    └──────┬───────┘    └──────────────┘    └─────────┘ │
│                            │ /gateway/                                   │
│                            ▼                                             │
│                     ┌──────────────┐                                     │
│                     │ AI Gateway   │──────────────────────────▶ Ollama   │
│                     │ :8000        │                                     │
│                     └──────────────┘                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ Observability: Prometheus ← Node Exporter, cAdvisor; Grafana :3001  │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│  Host hardening: UFW, Fail2ban, non-root admin, key-based SSH         │
└─────────────────────────────────────────────────────────────────────────┘
```

The repository root README documents the **application layer** (MCP tools, investigation workflows, v1.0 milestone). This blueprint documents the **platform layer** (hosting, containers, networking, security posture, and planned observability).

---

## Current Components

| Component | Role | Status |
| --------- | ---- | ------ |
| **DigitalOcean VPS** | Cloud host for the self-hosted AI stack | Deployed |
| **Ubuntu** | Linux OS; Docker runtime and future monitoring agents | Deployed |
| **Docker Compose** | Declarative multi-container deployment (`platform/docker-compose.yml`) | Deployed |
| **Ollama** | Local LLM inference API (`ollama/ollama` image) | Optional (`ai` profile) |
| **Open WebUI** | Browser chat UI connected to Ollama | Deployed (internal; proxied via Nginx at `/`) |
| **AI Gateway** | FastAPI proxy to Ollama; foundation for routing, logging, and security testing | Optional (`ai` profile; `/gateway/` via Nginx) |
| **Nginx** | Reverse proxy; public entry point on port 80 | Deployed |
| **Prometheus** | Metrics collection and time-series storage | Deployed |
| **Node Exporter** | Host-level metrics (CPU, memory, disk, network) | Deployed |
| **cAdvisor** | Per-container resource metrics | Deployed |
| **Grafana** | Dashboards and exploration UI on port 3001 | Deployed |
| **gemma2:2b** | Small local model for chat and experimentation | Installed and tested |
| **MCP lab** | `scripts/soc_mcp_server.py` — SOC investigation tools via MCP | v1.0 (see root README) |

### Docker Compose services

Defined in `platform/docker-compose.yml`:

- **ollama** — Model backend with persistent volume `ollama:/root/.ollama` (internal only); **`profiles: ["ai"]`**
- **open-webui** — Web frontend; `OLLAMA_BASE_URL=http://ollama:11434`; not published to the host; core profile
- **ai-gateway** — FastAPI service built from `platform/ai-gateway/`; `OLLAMA_BASE_URL=http://ollama:11434`; not published to the host; **`profiles: ["ai"]`**
- **nginx** — Reverse proxy on host port **80**; config at `platform/nginx/default.conf`; routes `/` to Open WebUI and `/gateway/` to AI Gateway (502 when ai-gateway is stopped)
- **prometheus** — Metrics TSDB; config at `platform/prometheus/prometheus.yml`; volume `prometheus`
- **node-exporter** — Host metrics on `:9100` (internal); mounts `/proc`, `/sys`, and host root
- **cadvisor** — Container metrics on `:8080` (internal); reads Docker runtime state
- **grafana** — Dashboards on host port **3001**; volume `grafana` for persistent state

### Observability stack

| Component | What it does |
| --------- | ------------ |
| **Prometheus** | Pull-based monitoring system. On a schedule defined in `prometheus.yml`, it HTTP-scrapes metric endpoints, stores time-series samples in a local TSDB, and supports PromQL queries for dashboards and alerts. |
| **Node Exporter** | A Prometheus exporter that runs on the VPS and exposes hardware and OS metrics—CPU load, memory usage, disk space, network I/O—from `/proc`, `/sys`, and the root filesystem. |
| **cAdvisor** | Container Advisor: discovers running Docker containers and exports their resource usage (CPU, memory, filesystem, network) so operators can see which services consume capacity. |
| **Grafana** | Visualization and exploration front end. Connects to Prometheus as a data source and renders dashboards for host health, container utilization, and trends over time. |

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  Observability data path (Docker network — scrape targets internal)    │
│                                                                         │
│   Node Exporter (:9100) ──┐                                            │
│   cAdvisor (:8080) ───────┼──▶ Prometheus (:9090) ──▶ Grafana (:3001) │
│   Prometheus (self) ──────┘         TSDB volume              ▲ public   │
│                                                               │         │
│                                                    Operator browser     │
└─────────────────────────────────────────────────────────────────────────┘
```

### MCP lab (application layer)

The MCP server is configured in `.cursor/mcp.json` and exposes tools such as:

- Alert classification and SSH / command-execution investigation workflows
- Multi-alert correlation and attack-chain analysis
- Detection engineering outputs (Sigma, KQL, Splunk SPL, QRadar AQL)
- Incident reporting, analyst decision review, and Markdown export

The MCP layer uses **deterministic, bounded tools** — no arbitrary code execution by the model. Path access is restricted to the lab directory. See the root [README.md](../../README.md) for the full tool catalog.

---

## Planned Components

| Component | Purpose |
| --------- | ------- |
| **HTTPS / TLS** | Encrypt traffic in transit (Let's Encrypt or similar); terminate TLS at Nginx |
| **Grafana dashboards & alerting** | Pre-built dashboards, disk/container alerts, authenticated access behind Nginx |
| **promptfoo** | Structured prompt evaluation and regression testing for AI workflows (target: AI Gateway) |
| **garak** | LLM vulnerability and probe testing (jailbreaks, prompt injection, data leakage patterns; target: AI Gateway) |
| **GitHub Actions** | CI for MCP server tests, linting, and repeatable security checks on pull requests |

These components are intentionally staged: establish a stable, hardened base first, then add observability and AI-specific security testing.

---

## Traffic Flow

### Current (production-like lab path)

```text
Analyst / Developer Browser
        │
        │  HTTP (port 80)
        ▼
Nginx container (:80)
        │
        │  HTTP (Docker network)
        ▼
Open WebUI container (:8080 internal)
        │
        │  HTTP (Docker network)
        ▼
Ollama container (:11434 internal)
        │
        ▼
gemma2:2b (loaded in Ollama)
```

### AI Gateway path (deployed)

```text
Client (curl, promptfoo, garak, MCP tooling)
        │
        │  HTTP /gateway/ (port 80)
        ▼
Nginx container (:80)
        │
        │  HTTP (Docker network)
        ▼
AI Gateway container (:8000 internal)
        │
        │  HTTP (Docker network)
        ▼
Ollama container (:11434 internal)
        │
        ▼
gemma2:2b (loaded in Ollama)
```

Nginx (port 80) and Grafana (port 3001) are published on host ports. Ollama, Open WebUI, AI Gateway, Prometheus, Node Exporter, and cAdvisor stay on the internal Docker network, which reduces the attack surface.

### Developer / MCP path (local or SSH session)

```text
Cursor (or MCP client)
        │
        │  stdio / MCP protocol
        ▼
soc-assistant (Python FastMCP)
        │
        ├── Read sample alerts / logs (lab directory only)
        ├── Deterministic parsing, scoring, query generation
        └── JSON structured responses to the agent
```

### Observability path (deployed)

```text
Operator Browser
        │
        │  HTTP :3001
        ▼
Grafana container
        │
        │  PromQL (Docker network)
        ▼
Prometheus container
        ▲
        │  scrape every 15s
        ├── Node Exporter (host metrics)
        ├── cAdvisor (container metrics)
        └── Prometheus (self-monitoring)
```

### Target state (after HTTPS)

```text
Internet / VPN
        │
        │  HTTPS :443 (planned — TLS not yet configured)
        ▼
Nginx (TLS termination, rate limits, access controls)
        │
        ├── /          → Open WebUI → Ollama
        ├── /gateway/  → AI Gateway → Ollama
        └── /grafana   → Grafana (authenticated; port 3001 direct access today)

GitHub Actions (on push/PR)
        │
        └── Test MCP server, run promptfoo/garak jobs (planned)
```

---

## Security Model

The platform follows **defense in depth** and **least privilege**, appropriate for a learning lab that may later face untrusted input during AI security testing.

### Host layer (VPS)

| Control | Implementation |
| ------- | -------------- |
| Administrative access | SSH key authentication; non-root user (`sysadmin`) |
| Brute-force mitigation | Fail2ban |
| Network filtering | UFW firewall |
| Privilege reduction | Root SSH login disabled |
| Service isolation | Workloads run in Docker containers |

### Container layer

| Control | Implementation |
| ------- | -------------- |
| Minimal exposure | Nginx :80 and Grafana :3001 published; AI and scrape targets internal |
| Internal networking | Open WebUI, AI Gateway, Ollama, Prometheus, Node Exporter, and cAdvisor on Docker network only |
| Persistence | Named volumes for models, WebUI data, Prometheus TSDB, and Grafana state |
| Restart policy | `unless-stopped` for availability during reboots |

### Application layer (MCP lab)

| Control | Implementation |
| ------- | -------------- |
| Bounded file access | Tools resolve paths under the lab root only |
| No blind execution | Tools return structured data; agents reason over outputs |
| Lab-only telemetry | Real host logs referenced in `.gitignore`; samples for learning |
| Human in the loop | Investigations produce recommendations, not autonomous containment |

### Planned security enhancements

- TLS for all browser traffic (HTTPS via Nginx)
- Authentication in front of Open WebUI and Grafana
- Automated LLM security probes (garak) and prompt regression tests (promptfoo)
- CI gates (GitHub Actions) before merging changes to MCP tools
- Secret management via environment variables — never committed to the repository

---

## Future Roadmap

### Phase 1 — Platform hardening (in progress)

- [x] VPS provisioning and host hardening
- [x] Docker Compose stack (Ollama + Open WebUI)
- [x] Local model (`gemma2:2b`) validated
- [x] Nginx reverse proxy
- [x] AI Gateway (FastAPI proxy to Ollama)
- [ ] HTTPS with automated certificate renewal

### Phase 2 — Observability

- [x] Prometheus + Node Exporter + cAdvisor
- [x] Grafana on port 3001 with persistent volume
- [ ] Pre-built Grafana dashboards (CPU, memory, container health)
- [ ] Basic alerting (disk, container down, high load)

### Phase 3 — AI security engineering

- [ ] promptfoo suites for SOC prompt templates and tool-use scenarios
- [ ] garak probe runs against self-hosted models
- [ ] Document findings and mitigations in `platform/docs/`

### Phase 4 — Integration and CI

- [ ] GitHub Actions: unit tests (`scripts/test_soc_mcp_server.py`), lint, optional security scans
- [ ] Tighter integration between Open WebUI and MCP workflows (where appropriate)
- [ ] Optional threat-intel and case-management integrations (root README future items)

### Phase 5 — SOC lab expansion

- Malware and PowerShell investigation workflows
- Detection validation test cases
- Broader SIEM and SOAR integration patterns

---

## Interview-Ready Explanation

Use this narrative in interviews, cover letters, or README intros.

> **Elevator pitch (30 seconds)**  
> I built an AI Security Engineering Platform that pairs a self-hosted LLM stack on a hardened DigitalOcean VPS with a custom MCP server for SOC workflows. The platform shows I can operate AI infrastructure safely—Docker, networking, host hardening—and build agent tooling that is bounded and auditable rather than giving models unrestricted shell access.

> **Technical depth (2 minutes)**  
> On the infrastructure side, I run Ubuntu on a VPS with UFW, Fail2ban, and SSH key-only access. Ollama and Open WebUI are deployed with Docker Compose behind an Nginx reverse proxy on port 80, with a FastAPI AI Gateway at `/gateway/` for programmatic access and future promptfoo/garak integration. Prometheus, Node Exporter, cAdvisor, and Grafana provide host and container observability. AI and scrape targets stay on the internal Docker network; Grafana is on port 3001 for dashboards. I use a small model (`gemma2:2b`) for cost-effective local experimentation.
>  
> On the application side, I wrote a Python MCP server that exposes dozens of security tools—alert parsing, MITRE mapping, multi-alert correlation, detection rule drafts for multiple SIEMs, and incident report generation. The AI agent orchestrates these tools through MCP; each tool is deterministic and returns structured JSON. That design mirrors how production security copilots should work: the model plans and explains; the tools enforce guardrails and repeatable logic.  
>  
> My roadmap adds HTTPS on Nginx, expanded Grafana dashboards and alerting, and promptfoo and garak for prompt evaluation and LLM security testing, plus GitHub Actions for CI. That progression moves the project from “working lab” to “portfolio-grade platform engineering with an AI security focus.”

> **Why it matters to employers**  
> Security teams need people who understand both **how to host and test AI systems safely** and **how to automate SOC work without introducing unbounded agent risk**. This repository demonstrates both: platform operations and security-aware agent design.

---

## Related Documentation

| Document | Description |
| -------- | ----------- |
| [../../README.md](../../README.md) | MCP lab, tools, workflows, v1.0 milestone |
| [architecture.md](./architecture.md) | Concise current platform architecture |
| [lab-notes.md](./lab-notes.md) | Deployment checklist and operational notes |
| [../README.md](../README.md) | Platform directory overview |
| [../docker-compose.yml](../docker-compose.yml) | Container definitions |

---

## Author

Sydney McGee — Cybersecurity Analyst | Security Automation | AI Security Engineering
