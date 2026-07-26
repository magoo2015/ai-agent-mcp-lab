# PROJECT_CONTEXT.md

**AI Agent MCP Lab / AI Security Engineering Platform**

Primary onboarding document for human engineers and AI coding assistants (Cursor, Claude Code, Gemini, ChatGPT, and similar). This file is the single source of truth for current architecture, capabilities, and development direction.

| Status label | Meaning |
| ------------ | ------- |
| **Implemented** | Present in the repository and operable as documented |
| **Planned** | Documented as near-term work; not fully shipped |
| **Future Ideas** | Parking-lot concepts; not committed design |

Do not treat Planned or Future Ideas as implemented features.

---

# 1. Project Overview

## Purpose

This repository is a **safe, offline-capable learning and portfolio lab** for AI security engineering. It combines:

1. A **self-hosted AI runtime** (Docker Compose on a hardened VPS): Nginx, Open WebUI, optional Ollama inference, a FastAPI AI Gateway, and Prometheus/Grafana observability.
2. An **SOC investigation automation layer** built on the Model Context Protocol (MCP): deterministic tools that accept normalized alert JSON and produce analyst-ready investigation packages, MITRE mappings, multi-SIEM query drafts, and Markdown reports—without live SIEM, EDR, or production API access.

## Long-term vision

Demonstrate **responsible AI security engineering**: host models safely, give agents **bounded tools** instead of open-ended shell access, evaluate prompt quality, observe infrastructure health, and automate repeatable SOC workflows (triage, MITRE framing, hunt queries, detection ideas, reporting) in a controlled lab.

The goal is **not** a commercial product. The goal is a production-*style* reference platform that shows platform operations and security-aware agent design together.

## Why this project exists

Security teams need people who understand both:

- How to **host and test AI systems safely** (containers, reverse proxy, auth, metrics, resource limits)
- How to **automate SOC work without unbounded agent risk** (structured tools, explicit limitations, human-in-the-loop)

This lab exists so those skills can be practiced and demonstrated without production credentials or live vendor APIs.

## Primary learning objectives

- AI agents, tool use, and MCP transports (stdio)
- FastAPI gateway design (provider routing, API-key auth, request limits, telemetry, Prometheus metrics)
- Docker Compose profiles for capacity-aware operation on small VPS hosts
- Offline SOC investigation automation (schemas, MITRE mapping, query generation, reports)
- Prompt libraries and promptfoo regression evaluation
- Observability (Prometheus, Node Exporter, cAdvisor, Grafana)
- Defensive cybersecurity automation and detection-engineering handoffs

## Target audience

- Cybersecurity analysts moving into automation / AI security engineering
- Detection engineers and SOC tooling designers
- Platform engineers with a security focus
- AI coding assistants continuing work on this repository

## Portfolio goals

Suitable as a GitHub portfolio piece for roles in AI security engineering, security automation, detection engineering, SOC workflow design, and security-focused platform engineering. Interview narratives and deeper platform security context live in `platform/docs/platform-blueprint.md`.

---

# 2. Current Architecture

## High-level conceptual stack

The platform has complementary layers. The diagram below matches the intended product story. **Important wiring notes follow**—Open WebUI and the MCP investigation server are **not** currently chained through the AI Gateway.

```text
User
  │
  ▼
Open WebUI  (browser chat via Nginx /)
  │
  │  (direct to Ollama today — see traffic flows)
  ▼
AI Gateway (FastAPI)  (programmatic path via Nginx /gateway/)
  │
  ▼
Ollama / OpenAI routing
  │
  │  (MCP is a separate offline path today — Planned: tighter gateway/MCP integration)
  ▼
MCP Investigation Server  (platform/mcp-server — stdio)
  │
  ▼
Investigation tools
  (investigate_alert, map_mitre, generate_queries)
```

## Accurate traffic flows (Implemented)

### Chat path (Open WebUI)

```text
User Browser
  ↓
Nginx :80 /
  ↓
Open WebUI :8080 (Docker network)
  ↓
Ollama :11434 (Docker network; requires Compose profile `ai`)
  ↓
tinyllama (default) / gemma2:2b (optional)
```

### Programmatic inference path (AI Gateway)

```text
Client (curl, promptfoo, automation)
  ↓  X-API-Key required for POST /chat
Nginx :80 /gateway/
  ↓
AI Gateway :8000 (Docker network only — no host :8000)
  ↓
provider=ollama → Ollama /api/generate
  or
provider=openai → OpenAI HTTPS (when OPENAI_API_KEY is set)
```

### Offline investigation path (MCP)

```text
MCP client (Cursor, demo_investigation.py, test_mcp_client.py)
  ↓  stdio / JSON-RPC
mcp_server.py  (soc-investigation-tools)
  ↓
tools/ (investigate_alert, mitre_mapper, query_generator)
  ↓
Structured JSON and/or Markdown SOC report
```

The platform MCP module does **not** call the AI Gateway. Investigation logic is deterministic and offline.

### Monitoring stack (Implemented)

```text
Operator Browser
  ↓
Nginx :80 /grafana/
  ↓
Grafana :3000 (internal; auth required; anonymous/signup disabled)
  ↓  PromQL
Prometheus (TSDB volume)
  ↑  scrape every 15s
  ├── Node Exporter :9100   (host CPU, memory, disk, network)
  ├── cAdvisor :8080        (per-container resources)
  ├── AI Gateway :8000 /metrics  (when `ai` profile is running)
  └── Prometheus :9090      (self-scrape)
```

| Component | Role |
| --------- | ---- |
| **Prometheus** | Pull-based metrics TSDB; config in `platform/prometheus/prometheus.yml` |
| **Grafana** | Authenticated dashboards UI behind Nginx at `/grafana/` |
| **Node Exporter** | Host metrics from `/proc`, `/sys`, root filesystem |
| **cAdvisor** | Per-container CPU, memory, filesystem, network metrics |

### Compose profiles

| Profile | Services | Status |
| ------- | -------- | ------ |
| *(default)* | nginx, open-webui, prometheus, grafana, node-exporter, cadvisor | Implemented |
| `ai` | ollama, ai-gateway | Implemented (optional) |
| `mcp` | mcp-server (one-shot / stdio) | Implemented |
| `eval` | promptfoo | Implemented |
| `tls` | certbot | Implemented (bootstrap); full HTTPS activation **Planned** |

### How components interact

| From | To | Interaction |
| ---- | -- | ----------- |
| Browser | Nginx | Sole public entry (ports 80/443 reserved; bootstrap listens on HTTP :80) |
| Nginx | Open WebUI | Proxies `/` |
| Nginx | AI Gateway | Proxies `/gateway/`; forwards `X-API-Key` |
| Nginx | Grafana | Proxies `/grafana/` |
| Open WebUI | Ollama | `OLLAMA_BASE_URL=http://ollama:11434` |
| AI Gateway | Ollama / OpenAI | Provider modules in `providers/` |
| Prometheus | Exporters + gateway | Internal scrapes; `/metrics` not public via Nginx |
| MCP client | mcp-server | Stdio only; no published ports |
| promptfoo | AI Gateway | HTTP `POST http://ai-gateway:8000/chat` on Compose network |

### Two MCP surfaces (do not conflate)

| Surface | Location | Server name | Status |
| ------- | -------- | ----------- | ------ |
| **Platform offline investigation tools** | `platform/mcp-server/` | `soc-investigation-tools` | Primary Dockerized investigation engine |
| **Workstation SOC assistant** | `scripts/soc_mcp_server.py` | `soc-assistant` | Extended FastMCP tool catalog for local Cursor use; paths in `.cursor/mcp.json` are host-specific |

---

# 3. Repository Structure

```text
ai-agent-mcp-lab/
├── PROJECT_CONTEXT.md          # This document
├── README.md                   # Public project overview
├── CHANGELOG.md                # Milestone history
├── LICENSE
├── requirements.txt            # Root MCP SDK pin for scripts/soc_mcp_server.py
├── .cursor/                    # Cursor MCP config + lab rules
├── docs/                       # Diagrams and demo Markdown reports
├── notes/                      # Personal lab journal
├── platform/                   # Self-hosted AI + observability + offline MCP
├── sample_data/                # Legacy root alert samples for soc-assistant
└── scripts/                    # Workstation MCP server + tests
```

## `platform/` — infrastructure and offline investigation engine

**Purpose:** Deployable AI security platform and the Dockerized offline SOC MCP tools.

**Responsibilities:** Compose orchestration, reverse proxy, gateway, observability, prompts, promptfoo, TLS bootstrap assets, and `mcp-server`.

| Path | Role |
| ---- | ---- |
| `docker-compose.yml` | Service definitions, profiles, volumes, resource limits |
| `.env.example` | Documented env vars (copy to `.env`; never commit secrets) |
| `ai-gateway/` | FastAPI gateway, providers, metrics, telemetry, hardening tests |
| `mcp-server/` | Offline CLI, MCP stdio server, demo runner, sample alerts, schemas, tools, report layer |
| `nginx/` | Reverse proxy config (`default.conf`, TLS template) |
| `prometheus/` | Scrape config |
| `grafana/` | Volume mount point (provisioned dashboards **Planned**) |
| `certbot/` | ACME webroot and cert storage placeholders |
| `prompts/` | SOC analyst prompt templates |
| `promptfoo/` | Evaluation config |
| `scripts/` | `deploy.sh`, `start-ai.sh`, `stop-ai.sh`, `status.sh`, `stop.sh` |
| `docs/` | Architecture, gateway, observability, Grafana, TLS, promptfoo, blueprint |

## `docs/` — portfolio artifacts

**Purpose:** Architecture visuals and example investigation report output.

| Path | Role |
| ---- | ---- |
| `docs/images/` | Architecture diagram (SVG/PNG/drawio) |
| `docs/demo-output/` | Markdown SOC reports from MCP demos |
| `docs/project_context.md` | Empty placeholder (superseded by root `PROJECT_CONTEXT.md`) |

## `scripts/` — workstation MCP lab

**Purpose:** Extended `soc-assistant` FastMCP server used from Cursor on a developer workstation.

**Responsibilities:** Broad SOC tool catalog (parse alerts, score, correlate, detection packages, incident workflows, Markdown export, etc.). Not the Docker Compose `mcp` profile image.

**Important files:** `soc_mcp_server.py`, `test_soc_mcp_server.py`

## `sample_data/` — legacy lab fixtures

**Purpose:** Sample Wazuh / command-execution JSON for the root `soc-assistant` workflows.

**Note:** Platform MCP samples live under `platform/mcp-server/sample_data/` (SSH, Defender, Proofpoint).

## `notes/` — learning journal

**Purpose:** Session notes and conceptual insights (`lab_journal.md`). Not runtime config.

## `.cursor/` — editor integration

| Path | Role |
| ---- | ---- |
| `mcp.json` | Registers filesystem + `soc-assistant` MCP servers (host paths may need local adjustment) |
| `rules/ai-agent-lab.mdc` | Always-on safety and teaching rules for this lab |

---

# 4. Current Capabilities

Documented below are **Implemented** features only.

## AI Platform

| Capability | Details |
| ---------- | ------- |
| **AI Gateway** | FastAPI service: `GET /health`, `GET /models`, `GET /metrics`, `POST /chat`; provider routing; latency telemetry; Prometheus metrics |
| **Authentication** | `X-API-Key` required for `POST /chat` (`GATEWAY_API_KEY`); constant-time compare; fail-closed if unset (503) |
| **Ollama integration** | Default provider; Compose `ai` profile; default model `tinyllama` |
| **OpenAI routing** | Optional `provider=openai` when `OPENAI_API_KEY` is configured |
| **Request hardening** | `MAX_PROMPT_CHARS`, `MAX_REQUEST_BYTES`; empty-prompt rejection |
| **Open WebUI** | Browser chat UI behind Nginx `/` |
| **Nginx** | Public entry; routes `/`, `/gateway/`, `/grafana/`; denies public metrics paths |
| **Compose profiles** | Core vs `ai` vs `mcp` vs `eval` vs `tls` for capacity control |

## SOC Investigation (platform MCP)

| Capability | Details |
| ---------- | ------- |
| **MCP server** | `soc-investigation-tools` over stdio (`mcp_server.py`) |
| **Offline CLI** | `main.py` → JSON investigation package |
| **MITRE mapping** | Deterministic `alert_type` → ATT&CK technique (`map_mitre` / `mitre_mapper.py`) |
| **Investigation package** | Summary, severity assessment, MITRE, queries, next steps, detection opportunities, confidence (0–100), limitations |
| **Detection query generation** | QRadar AQL, Sentinel KQL, Defender Advanced Hunting KQL, OpenSearch DQL drafts |
| **Investigation report generation** | Structured `InvestigationReport` layer (`reports/`) + Markdown renderer; `demo_investigation.py` builds the report then renders (examples under `docs/demo-output/`) |
| **Deterministic evidence extraction** | `extract_evidence(alert)` populates `InvestigationReport.evidence` from normalized alert fields only (`EVID-###`); Markdown evidence table; no `raw_event` parsing |
| **Structured analyst reasoning** | `build_analyst_reasoning(alert, evidence)` → evidence-linked `AnalystReasoning` (`OBS/ASM/ALT/GAP-###`); report-layer only |
| **Structured confidence rationale** | `build_confidence_rationale(alert, evidence)` → `ConfidenceRationale` (`SUP/LIM-###`); context for (not a reproduction of) the numeric score; report-layer only |
| **Sample alerts** | SSH failed login (Wazuh-shaped), Defender suspicious process, Proofpoint phishing |

## Workstation MCP (`scripts/soc_mcp_server.py`)

Extended FastMCP tools including alert parsing, SSH/command investigation, correlation, detection engineering (Sigma, Sentinel, QRadar, Splunk), incident reporting, and Markdown export. Configured via `.cursor/mcp.json` as `soc-assistant`.

## Prompt evaluation

| Capability | Details |
| ---------- | ------- |
| **Prompt library** | `alert_summary`, `mitre_mapping`, `detection_recommendation`, `executive_summary` |
| **Promptfoo** | Docker `eval` profile; 4 active SSH-scenario evaluations against AI Gateway + `tinyllama` |

## Observability

| Capability | Details |
| ---------- | ------- |
| **Prometheus metrics** | Scrapes Node Exporter, cAdvisor, self, and AI Gateway `/metrics` |
| **Grafana** | Authenticated UI at `/grafana/`; persistent volume |
| **Resource limits** | Grafana and promptfoo Compose memory/CPU caps for small VPS |

### Not implemented (do not document as done)

- Full HTTPS/TLS activation (bootstrap prepared — **Planned**)
- Pre-built Grafana dashboards and alerting (**Planned**)
- Live SIEM/EDR/threat-intel connectors (**Future Ideas**)
- AI Gateway ↔ MCP investigation coupling (**Planned** / Future)
- GitHub Actions CI (**Planned**)
- garak LLM security testing (**Planned**)

---

# 5. Investigation Workflow

## Platform offline MCP flow (primary demo path)

Actual workflow from `platform/mcp-server/` (`investigate_alert` orchestration + optional Markdown demo):

```text
Normalized alert JSON
  (e.g. sample_data/ssh_failed_login.json)
        ↓
AlertInput
        ↓
investigate_alert()    → InvestigationOutput
        ↓
extract_evidence(alert) → EvidenceItem[]   (reports/evidence.py)
        ↓
build_analyst_reasoning(alert, evidence) → AnalystReasoning  (reports/reasoning.py)
        ↓
build_confidence_rationale(alert, evidence) → ConfidenceRationale  (reports/confidence.py)
        ↓
build_investigation_report()  (reports/builder.py — thin adapter)
        ↓
InvestigationReport    (reports/models.py)
        ↓
render_markdown()      (reports/markdown_renderer.py)
        ↓
Console Output / file  (demo_investigation.py; examples in docs/demo-output/)
```

Inside `investigate_alert`, MITRE mapping, query generation, severity, confidence,
next steps, detection opportunities, and limitations are unchanged. The report
layer copies that package into structured fields, attaches deterministic evidence,
evidence-linked analyst reasoning, structured confidence rationale, and a
report-only recommended disposition from normalized `AlertInput` fields only, and
renders Markdown; it does not recalculate investigation logic or parse `raw_event`.

**Evidence (Implemented — Version 1.1 Phase 2):** `extract_evidence(alert)` builds
`EvidenceItem` rows (`EVID-001`, `EVID-002`, …) from present normalized metadata
and observables. Missing / blank / whitespace-only fields are omitted. MITRE
ATT&CK mappings remain classification in the MITRE section and are not duplicated
as evidence. Threat-intelligence enrichment and `raw_event` parsing are **not**
implemented.

**Analyst reasoning (Implemented — Version 1.1 Phase 3):**
`build_analyst_reasoning(alert, evidence)` populates structured
`AnalystReasoning` with observations, assessment, alternative explanations, and
evidence gaps. Statements use stable IDs (`OBS-###`, `ASM-###`, `ALT-###`,
`GAP-###`) and reference evidence by ID only. Scenario templates cover
`ssh_failed_login`, `phishing_email`, and `suspicious_process`; unknown alert
types receive a conservative fallback (no generic alternative explanations).
Reasoning is deterministic template text — not LLM-generated — and does not
confirm compromise or replace analyst judgment.

**Confidence rationale (Implemented — Version 1.1 Phase 4):**
`build_confidence_rationale(alert, evidence)` populates structured
`ConfidenceRationale` with supporting factors (`SUP-###`), limiting factors
(`LIM-###`), and an overall summary. Supporting factors reference present
normalized evidence; limiting factors describe missing telemetry (normally
without evidence IDs). Scenario templates cover the same three alert types as
reasoning, with a conservative unknown-alert fallback. The rationale provides
context for the reported numeric confidence score using normalized evidence
only — it does **not** recalculate, validate, or mathematically reproduce
`_compute_confidence()`. Inputs such as alert-type familiarity, `raw_event`
presence, and MITRE confidence that may affect the numeric score are **not**
necessarily reflected in the rationale.

**Recommended disposition (Implemented — Version 1.1 Phase 5):**
`build_recommended_disposition(alert, evidence)` populates structured
`RecommendedDisposition` with a controlled two-label vocabulary
(`Suspicious Activity` / `Insufficient Evidence`), a fixed rationale template,
optional evidence-grounded `EVID-###` references, and
`analyst_review_required=True` on every Version 1.1 path. Disposition is
deterministic, advisory, and report-only — it does **not** close incidents,
trigger containment, disable accounts, or change confidence, severity, or
MITRE. Scenario handlers cover `ssh_failed_login`, `phishing_email`, and
`suspicious_process`; unknown alert types always return `Insufficient Evidence`
(generic observables alone are not enough). Benign, likely-malicious,
true-positive, and false-positive labels are intentionally absent. No
confidence or severity thresholds and no `raw_event` parsing. Timeline remains
unpopulated. MCP `investigate_alert` and CLI JSON output contracts are unchanged
(evidence, reasoning, confidence rationale, and disposition are report-layer
only).

`InvestigationReport` still reserves an empty expansion point for timeline —
not yet populated.

MCP tools can also be called independently:

| Tool | Output |
| ---- | ------ |
| `investigate_alert` | Full investigation package |
| `map_mitre` | Primary MITRE mapping object |
| `generate_queries` | Query language buckets |

Supported MITRE-mapped `alert_type` values today: `ssh_failed_login`, `suspicious_process`, `phishing_email`, `dlp_alert`, `aws_iam_change` (unknown types return a low-confidence unmapped result).

## Prompt-library path (LLM-assisted, separate)

```text
Alert / findings text
  ↓
Render platform/prompts/*.md
  ↓
POST /gateway/chat  (X-API-Key)
  ↓
Model response (JSON-shaped intent; tinyllama may be imperfect)
  ↓
promptfoo assertions (SSH suite) or analyst review
```

---

# 6. Component Responsibilities

## Nginx

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Public HTTP entry, path routing, ACME challenge serving, forwarding gateway API key header | Inference, investigation logic, metrics storage, TLS issuance until activated |

## Open WebUI

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Browser chat UX to Ollama | Gateway auth, MCP tools, Prometheus scraping |

## AI Gateway

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Stable `/chat` contract, provider selection, API-key auth, size limits, telemetry, Prometheus metrics | UI rendering, MCP investigation logic, live SIEM queries, storing conversations |

## Ollama

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Local model serve/generate API | Auth for the lab edge, routing policy, SOC tooling |

## OpenAI provider (gateway module)

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Cloud chat calls when configured | Default offline demos, secret storage in git |

## MCP investigation server (`platform/mcp-server`)

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Deterministic offline investigation packages, MITRE templates, query drafts, stdio MCP transport, Markdown demos | Calling AI Gateway, live vendor APIs, publishing network ports, overstating confidence |

## Workstation `soc-assistant` (`scripts/soc_mcp_server.py`)

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Broader local MCP tool catalog for Cursor lab workflows | Docker Compose `mcp` image contents, VPS runtime services |

## Prompt library + promptfoo

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Versioned SOC prompt contracts; regression assertions against gateway outputs | Replacing deterministic MCP tools; production detection deployment |

## Prometheus / exporters / Grafana

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Host/container/gateway metrics collection and visualization | Application business logic, investigation correctness |

## Helper scripts (`platform/scripts/`)

| Responsible for | Not responsible for |
| --------------- | ------------------- |
| Deploy/start/stop/status convenience around Compose | Changing application code or issuing TLS certs automatically |

---

# 7. Development Principles

These principles are derived from lab rules, platform docs, and existing code patterns.

1. **Keep components modular** — Gateway routing ≠ provider HTTP ≠ investigation tools ≠ prompt templates.
2. **Build incrementally** — One focused change at a time; prefer Compose profiles over always-on heavy services.
3. **Avoid unnecessary complexity** — Offline deterministic tools before live connectors; stdio MCP before network transports.
4. **Separate investigation logic from presentation** — Core packages are structured data (`InvestigationOutput` → `InvestigationReport`); Markdown/UI are renderers (`reports/markdown_renderer.py`, driven by thin demos like `demo_investigation.py`).
5. **Test before committing** — Gateway unittest, MCP report/unittest suite, MCP client smoke tests, root MCP tests, promptfoo when prompts/gateway change.
6. **Prefer readability** — Clear module names, stderr-only logging on MCP stdio servers, explicit limitations in outputs.
7. **Production-style architecture** — Reverse proxy as sole edge, internal scrape targets, secrets in env, fail-closed auth where applicable—even in a lab.
8. **Explain WHY before HOW** — Especially for AI assistants and learners; document trade-offs (e.g. why Ollama is optional on 2 vCPU / 4 GB).
9. **Bounded tools, human in the loop** — Tools extract/structure; models and analysts reason; no autonomous containment.
10. **Protect secrets and the host** — No keys in git; ask before adding packages; no destructive ops without explicit approval (see `.cursor/rules/ai-agent-lab.mdc`).
11. **Conservative confidence** — Do not imply maliciousness without supporting evidence; surface assumptions and limitations.

---

# 8. Development Workflow

## Expected engineering loop

```text
Plan
  ↓
Implement
  ↓
Test
  ↓
Review
  ↓
Commit
  ↓
Push
  ↓
Next Phase
```

Guidance:

1. **Plan** — Read this file and relevant `platform/docs/*`; decide Implemented vs Planned scope.
2. **Implement** — Small PR-sized changes; keep offline tests green without credentials.
3. **Test** — Run the commands in §9 that match the touched area.
4. **Review** — Diff for secrets, scope creep, and architectural drift (§6).
5. **Commit** — Only when the human requests a commit; clear why-focused message.
6. **Push / PR** — Feature branches and GitHub PRs are used on this repo; do not force-push `main`.
7. **Next Phase** — Prefer items in §12 before parking-lot §13 ideas.

## Git workflow currently used

Observed from repository history:

- Default branch: `main`
- Feature / docs branches merged via pull requests (e.g. investigation demo, architecture diagram)
- Conventional, descriptive commit subjects (docs, platform features, hardening, MCP, promptfoo)
- Do not amend published history or skip hooks unless explicitly requested

---

# 9. Common Commands

Run platform commands from `platform/` unless a script path is given (scripts resolve `platform/` themselves). Copy `.env.example` → `.env` and set `GRAFANA_ADMIN_PASSWORD` (and gateway keys as needed) before first deploy.

## Starting services

```bash
# Core stack: Nginx, Open WebUI, Prometheus, Grafana, exporters
./platform/scripts/deploy.sh

# Optional local inference + AI Gateway
./platform/scripts/start-ai.sh
# equivalent: cd platform && docker compose --profile ai up -d
```

## Stopping services

```bash
# Stop Ollama + AI Gateway only (core stays up)
./platform/scripts/stop-ai.sh

# Stop all Compose services (volumes preserved)
./platform/scripts/stop.sh
```

## Viewing logs / status

```bash
./platform/scripts/status.sh

cd platform
docker compose ps
docker compose logs --tail=50 nginx open-webui ai-gateway ollama grafana
```

## Restarting containers

```bash
cd platform
docker compose restart nginx
docker compose --profile ai up -d --force-recreate ai-gateway
```

## MCP investigation demo

```bash
cd platform

docker compose --profile mcp build mcp-server

docker compose --profile mcp run --rm mcp-server \
  python demo_investigation.py sample_data/ssh_failed_login.json

# Offline JSON CLI
docker compose --profile mcp run --rm mcp-server \
  python main.py sample_data/ssh_failed_login.json

# MCP stdio server (client-driven)
docker compose --profile mcp run --rm -i mcp-server python mcp_server.py

# MCP client smoke test
docker compose --profile mcp run --rm mcp-server \
  python test_mcp_client.py
```

## Promptfoo

```bash
./platform/scripts/start-ai.sh   # gateway + ollama required
cd platform
docker compose --profile eval run --rm promptfoo eval -c /config/promptfooconfig.yaml
```

## Health checks

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost
curl -s http://localhost/gateway/health
# Chat requires X-API-Key matching GATEWAY_API_KEY in platform/.env
curl -s http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-local-gateway-key>" \
  -d '{"prompt": "Say hello in one sentence."}'
```

## Tests

```bash
# AI Gateway hardening tests
cd platform/ai-gateway
GATEWAY_API_KEY=test-gateway-key-not-for-production \
  MAX_PROMPT_CHARS=100 \
  MAX_REQUEST_BYTES=1024 \
  python -m unittest test_hardening.py

# Platform MCP client test (Docker preferred)
cd platform
docker compose --profile mcp run --rm mcp-server python test_mcp_client.py

# Workstation soc-assistant tests (from repo root; needs local deps/paths)
python scripts/test_soc_mcp_server.py
```

---

# 10. Coding Standards

Based on patterns already present in the repository.

## Python style

- Python 3 with `from __future__ import annotations` where used
- Type hints on public functions; Pydantic models for alert I/O (`schemas/alert_schema.py`)
- FastAPI + Pydantic for gateway request bodies
- Prefer stdlib + small dependency sets (`fastapi`, `httpx`, `prometheus_client`, `mcp`, `pydantic`)
- Ask before adding new packages (lab rule)

## Folder organization

- `platform/ai-gateway/providers/` — upstream HTTP only
- `platform/mcp-server/tools/` — investigation logic
- `platform/mcp-server/schemas/` — shared alert / investigation I/O models
- `platform/mcp-server/reports/` — structured report models, evidence extraction, builder, Markdown renderer
- Entry points (`main.py`, `mcp_server.py`, `demo_investigation.py`) stay thin

## Module responsibilities

- Gateway `main.py`: auth, limits, routing, metrics hooks—not vendor SDK details
- MCP `mcp_server.py`: transport + tool registration—not reimplemented investigation logic
- Tools return structured data (`InvestigationOutput`); `reports/` extracts alert evidence, adapts to `InvestigationReport`, and renders Markdown; demos stay thin

## Naming conventions

- Snake_case functions and modules
- Alert types normalized to snake_case (`ssh_failed_login`)
- Compose service/container names match role (`ai-gateway`, `mcp-server`)
- Env vars uppercase (`GATEWAY_API_KEY`, `DEFAULT_MODEL`)

## Logging

- MCP stdio servers: **stderr only** for logs (stdout is JSON-RPC)
- Gateway telemetry: metadata JSON to stdout—**never** prompts, API keys, or secrets
- Avoid logging `raw_event` or sensitive observables by default

## Comments

- Module docstrings explain purpose and transport constraints
- Prefer clarity over cleverness; comment *why* for security-sensitive choices

## Testing philosophy

- Deterministic offline fixtures over live APIs
- Focused unit tests for auth/limits (`test_hardening.py`)
- MCP transport smoke tests (`test_mcp_client.py`)
- promptfoo as lightweight SOC language regression—not a substitute for analyst review
- Keep default eval suite small on constrained VPS hosts

---

# 11. Investigation Philosophy

The platform treats SOC automation as **evidence-grounded assistance**, not autonomous judgment.

## Distinguish clearly

| Category | Meaning |
| -------- | ------- |
| **Facts** | Observables and fields present in the alert / input (IPs, users, hosts, counts, vendor severity) |
| **Evidence** | Input-derived support cited for a claim or MITRE mapping |
| **Reasoning** | Analyst-facing interpretation, pivots, and next steps that may go beyond raw fields |
| **Conclusions** | Severity/confidence assessments that remain provisional until enrichment |

## Operating rules

- Do **not** imply maliciousness without supporting evidence.
- MITRE mappings are **templates with rationale and confidence**, not confirmed attributions.
- Recommended queries are **pivots**, not proof that events exist in a SIEM.
- Always surface **limitations** (offline, no live enrichment, schema variance).
- Prompt templates enforce grounded `observations` vs explicit `assumptions` / `missing_information`.
- Confidence scores are **conservative by design** (see `investigate_alert._compute_confidence` and mapper confidence labels).

## Reasoning process used in code

1. Normalize alert type and validate schema.
2. Map to MITRE with stated confidence and rationale.
3. Generate illustrative multi-SIEM queries from observables.
4. Build summary and severity narrative from vendor severity + alert-type context.
5. Attach next steps and detection opportunities for that alert family.
6. Compute overall confidence from mapping quality and observable richness.
7. List limitations so consumers cannot mistake offline drafts for live investigation results.

---

# 12. Current Roadmap

## Version 1.1 — In progress

Near-term investigation-report and demo improvements (treat as **Planned** unless marked Implemented):

| Item | Notes |
| ---- | ----- |
| Structured investigation reports | **Implemented (Phase 1)** — `reports/` models + builder + Markdown renderer; preserves `InvestigationOutput` / MCP contract |
| Evidence tables | **Implemented (Phase 2)** — `extract_evidence(alert)` → `EvidenceItem[]` with stable `EVID-###` IDs; Markdown table after Alert Overview; normalized fields only; no `raw_event` parsing; MITRE stays classification |
| Analyst reasoning | **Implemented (Phase 3)** — structured `AnalystReasoning` with evidence-linked statements; deterministic scenario templates (SSH / phishing / suspicious process) + conservative unknown fallback; Markdown after Evidence; no LLM; MCP/CLI contracts unchanged |
| Confidence assessment | **Implemented (Phase 4)** — structured `ConfidenceRationale` (`SUP-###` / `LIM-###`) from normalized evidence; context for (not a reproduction of) `_compute_confidence()`; Markdown after Analyst Reasoning; score remains engine-owned; MCP/CLI contracts unchanged |
| Investigation timelines | Planned expansion point on `InvestigationReport` (empty; not populated) |
| Final disposition | **Implemented (Phase 5)** — structured report-only `RecommendedDisposition` (`Suspicious Activity` / `Insufficient Evidence`); evidence-grounded `EVID-###` refs; deterministic scenario handlers + conservative unknown fallback; analyst review always required; no benign/likely-malicious/TP/FP labels; no automated closure or containment; no confidence/severity thresholds; no `raw_event` parsing; MCP/CLI contracts unchanged |
| Severity assessment | Deeper, evidence-tied severity narrative |
| Interactive demo runner | Improve `demo_investigation.py` UX / multi-sample flows |
| Platform-specific investigations | Stronger Wazuh / Defender / Proofpoint (and related) specialization |

*Already Implemented today (baseline for 1.1 Phases 1–5):* JSON investigation packages, reusable structured report layer (`InvestigationReport` + builder + Markdown renderer), deterministic evidence extraction from normalized alert fields, evidence-based structured analyst reasoning, structured confidence rationale (supporting/limiting factors; normalized evidence only; does not recalculate or fully reproduce the numeric score), structured recommended disposition (two-label controlled vocabulary; advisory only; analyst review always required), Markdown demo reports (evidence + analyst reasoning + confidence rationale + recommended disposition), severity assessment text, numeric confidence (engine-owned via `_compute_confidence()`), MITRE confidence, three sample platforms. Timeline remains unpopulated. Threat-intelligence enrichment and `raw_event` parsing are not implemented. MCP and CLI investigation output keys remain unchanged.

## Version 1.2 — Planned / later

| Item | Status |
| ---- | ------ |
| HTTPS/TLS activation (domain, certbot, redirect, security headers) | Planned (bootstrap exists) |
| Pre-built Grafana dashboards and basic alerting | Planned |
| Broader promptfoo scenarios (Defender, Proofpoint, AWS IAM) | Planned (documented, not active) |
| GitHub Actions CI (MCP tests, lint, optional eval) | Planned |
| Expanded workstation MCP workflows (malware, PowerShell, privilege escalation) | Planned / Future |

## Future

| Item | Status |
| ---- | ------ |
| garak LLM security testing against the AI Gateway | Future / Planned in blueprint |
| Tighter Open WebUI ↔ MCP integration | Future |
| Live threat-intel and case-management integrations | Future |
| Network MCP transports (beyond stdio) | Future — only if explicitly required |

---

# 13. Future Enhancements

Parking-lot ideas. **Not implemented.** Do not build these by default.

| Idea | Notes |
| ---- | ----- |
| Live SIEM/EDR/email integrations | QRadar, Defender, Sentinel, Wazuh, Proofpoint APIs |
| Threat intelligence enrichment | WHOIS, passive DNS, internal CMDB |
| VirusTotal | Hash/URL/IP enrichment |
| AbuseIPDB | IP reputation |
| URLScan | URL detonation / screenshot enrichment |
| Sigma improvements | Beyond draft generation toward validation pipelines |
| YARA / YARA-L | Malware and pipeline detection artifacts |
| SOAR integration | Ticket/case push; still human-approved actions |
| REST APIs for investigation packages | HTTP façade over offline tools |
| Interactive UI for investigations | Beyond Open WebUI chat and Markdown demos |
| Open WebUI traffic through AI Gateway | Architectural option; chat currently goes Ollama-direct |

---

# 14. Lessons Learned

Concise engineering lessons reflected in docs and design:

| Lesson | Takeaway |
| ------ | -------- |
| **Container resource limits** | Cap Grafana/promptfoo (and avoid always-on Ollama) on 2 vCPU / 4 GB hosts |
| **Compose profiles** | Split core UI/observability from heavy `ai` inference |
| **Gateway abstraction** | Stable `/chat` contract + provider modules simplifies OpenAI/Ollama and eval tooling |
| **Prompt evaluation** | Small, assertion-backed suites beat large flaky matrices on tiny models |
| **Offline investigation scenarios** | Deterministic sample alerts enable demos and regression without vendor credentials |
| **Docker architecture** | Nginx as sole edge; scrape targets internal; fail closed on missing gateway key |
| **MCP stdio hygiene** | Never print to stdout on the server process—protocol corruption is silent and painful |
| **Facts vs inference** | Tools structure facts; AI/analysts reason; outputs must label assumptions |

---

# 15. AI Session Handoff

Copy the following into a new AI conversation:

```text
You are working in the AI Agent MCP Lab / AI Security Engineering Platform repository.

Before writing or changing any code:

1. Read PROJECT_CONTEXT.md at the repository root end-to-end.
2. Understand the current architecture: Nginx edge, Open WebUI → Ollama (chat),
   AI Gateway → Ollama/OpenAI (programmatic), offline MCP investigation tools
   (platform/mcp-server) as a separate stdio path, plus Prometheus/Grafana monitoring.
3. Follow the Development Principles in PROJECT_CONTEXT.md.
4. Avoid unnecessary complexity. Prefer modular, incremental changes.
5. Clearly distinguish Implemented vs Planned vs Future Ideas. Do not invent features.
6. Continue from the documented roadmap (Version 1.1 first) unless I specify otherwise.
7. Explain design decisions (WHY) before implementation (HOW).
8. Separate investigation logic from presentation layers.
9. Protect secrets; ask before adding dependencies; no destructive git/filesystem ops
   without explicit approval.
10. Test the affected area before committing. Only commit when I explicitly ask.

Do not modify PROJECT_CONTEXT.md unless I ask you to update the source of truth.
```

---

## Related documentation

| Document | Purpose |
| -------- | ------- |
| [README.md](README.md) | Public overview and quick start |
| [platform/README.md](platform/README.md) | Platform ops and profiles |
| [platform/mcp-server/README.md](platform/mcp-server/README.md) | Offline MCP tools and demos |
| [platform/docs/architecture.md](platform/docs/architecture.md) | Traffic flows and components |
| [platform/docs/platform-blueprint.md](platform/docs/platform-blueprint.md) | Security model and interview narrative |
| [platform/docs/ai-gateway.md](platform/docs/ai-gateway.md) | Gateway hardening and providers |
| [platform/docs/promptfoo.md](platform/docs/promptfoo.md) | Eval setup |
| [platform/docs/observability.md](platform/docs/observability.md) | Metrics stack |
| [CHANGELOG.md](CHANGELOG.md) | Historical milestones |

---

*Last verified against the repository contents. Author: Sydney McGee — Cybersecurity Analyst · Security Automation · AI Security Engineering.*
