# Promptfoo Evaluation

This document describes the [promptfoo](https://www.promptfoo.dev/) setup for the AI Security Engineering Platform: what it does, how to run evaluations against the AI Gateway through Docker, and why prompt regression testing matters for SOC and detection-engineering workflows.

For gateway API details, see [../README.md](../README.md#ai-gateway). For prompt template design and variable contracts, see [prompt-library.md](./prompt-library.md). For architecture context, see [architecture.md](./architecture.md).

## Design principles

- **Docker only** — Promptfoo runs in a container so the VPS host does **not** need Node, npm, or npx.
- **Dev/eval tooling, not runtime** — Promptfoo is evaluation tooling. It is not part of the always-on platform (Nginx, Open WebUI, Grafana, Prometheus, Ollama, AI Gateway).
- **Resource limits** — The Compose service caps memory and CPU so eval jobs cannot starve the small VPS (2 vCPU / 4 GB RAM).
- **Low concurrency** — `maxConcurrency: 1` prevents multiple simultaneous model calls.
- **tinyllama only** — Day-to-day evals use `tinyllama`. `gemma2:2b` is too heavy for routine evaluation on this host.
- **Small default suite** — Default active tests are **4 evaluations** (4 prompt templates × 1 SSH scenario). Do not expand the default matrix on this VPS.
- **CI-ready** — The same `docker compose --profile eval run` pattern is intended for GitHub Actions and other CI/CD later.

## What Promptfoo Does

Promptfoo is an open-source framework for **evaluating LLM prompts** in a repeatable, version-controlled way. Instead of manually pasting prompts into a chat UI and eyeballing outputs, you define:

- **Prompts** — the text sent to the model (with variables for alert data, scenarios, etc.)
- **Providers** — where inference runs (here, the platform AI Gateway)
- **Tests** — example inputs plus **assertions** that check whether outputs meet minimum quality bars

Each `promptfoo eval` run produces a report you can compare over time. That makes it useful for:

- Regression testing after model or prompt changes
- Baseline checks before demos or portfolio reviews
- Lightweight quality gates on SOC assistant templates

This platform targets the **local AI Gateway** (`tinyllama` by default). No cloud APIs are configured.

## Configuration

Evaluations live in [`promptfoo/`](../promptfoo/):

| File | Purpose |
| ---- | ------- |
| [`promptfoo/promptfooconfig.yaml`](../promptfoo/promptfooconfig.yaml) | Provider, prompts, tests, and VPS-friendly concurrency |

The HTTP provider posts to the AI Gateway service on the Compose network:

```text
POST http://ai-gateway:8000/chat
Content-Type: application/json

{"model": "tinyllama", "prompt": "<eval prompt>"}
```

The gateway response field `response` is extracted via `transformResponse: json.response`.

Prompt paths are absolute inside the container (prompts are mounted at `/prompts`):

- `file:///prompts/alert_summary.md`
- `file:///prompts/mitre_mapping.md`
- `file:///prompts/detection_recommendation.md`
- `file:///prompts/executive_summary.md`

### Prompt library evaluation

The config evaluates the **AI SOC Analyst Prompt Library** in [`prompts/`](../prompts/). Each library template is loaded as a promptfoo prompt via `file://`:

| Prompt file | Sample input vars |
| ----------- | ----------------- |
| [`alert_summary.md`](../prompts/alert_summary.md) | `alert_data`, `investigation_context` |
| [`mitre_mapping.md`](../prompts/mitre_mapping.md) | `activity_description` |
| [`detection_recommendation.md`](../prompts/detection_recommendation.md) | `investigation_findings` |
| [`executive_summary.md`](../prompts/executive_summary.md) | `investigation_package` |

**How rendering works:** promptfoo substitutes `{{variable}}` placeholders in each `.md` template using `vars` from the test case. The full rendered document — including grounding rules and output schema — is sent to the AI Gateway `/chat` endpoint.

### Default active suite (VPS-safe)

**Active tests only:** SSH failed-login / brute-force scenario.

| Dimension | Count |
| --------- | ----- |
| Prompt templates | 4 |
| Active scenarios | 1 (SSH) |
| **Total evaluations** | **4** |

Each active scenario defines:

| Field | Purpose |
| ----- | ------- |
| `alert_json` | Condensed alert payload (also provided as `alert_data` for `alert_summary`) |
| `investigation_context` | Short analyst note grounding the case |
| `expected_focus` | What domain language the assertions target |
| Template-specific vars | `activity_description`, `investigation_findings`, `investigation_package` |

This keeps routine evals under control on a 2 vCPU / 4 GB host. A full multi-scenario matrix (for example 4 prompts × 4 scenarios = 16 cases) is too slow and resource-heavy for default use here.

### Future scenarios (not active)

The following alert types are **planned extensions**, not part of the default `tests:` list. Do **not** enable them on this VPS unless you intentionally accept a long, low-concurrency run.

| Scenario | Alert type | Intended `expected_focus` |
| -------- | ---------- | ------------------------- |
| Microsoft Defender endpoint | Suspicious process activity | Endpoint device, process, and suspicious or malware-like activity |
| Proofpoint phishing | Quarantined phishing email | Phishing email, user recipient, malicious URL or attachment |
| AWS IAM activity | Privilege change via CloudTrail | IAM user, API action, and permission or privilege change in cloud |

When a stronger host or CI runner is available, add one scenario at a time with scenario-specific assertions. Do not weaken assertions to force `tinyllama` through an oversized matrix.

**Why multiple scenarios matter (later):** SOC assistants must stay useful across auth, endpoint, email, and cloud signals. Multi-scenario coverage is the right long-term regression bar for Detection Engineering and AI Security Engineering work — but it is a **future** expansion, not the default on this lab VPS.

### Assertions

Tests enforce a shared quality bar plus **prompt-specific** SOC content checks on the SSH scenario.

**Shared (all templates via `defaultTest`):**

- `not-contains` refusal phrases: `I cannot`, `I'm unable`, `as an AI`
- `javascript` length check: `output.length > 50`

**Prompt-specific (SSH failed-login vars, one test per template):**

| Prompt | Content assertions |
| ------ | ------------------ |
| `alert_summary.md` | Must mention `ssh` (case-insensitive), plus at least one scenario token (`192.168.1.50`, `root`, `ubuntu-agent`, or auth-failure language) |
| `mitre_mapping.md` | Must include ATT&CK framing (`MITRE` or `ATT&CK`) and technique language (`T1110`, `Brute Force` / `brute-force`, or `technique`) |
| `detection_recommendation.md` | Must include `detection` or `rule`, **and** `threshold` or `failed` (not `rule` alone) |
| `executive_summary.md` | Must include `summary` or `risk`, and `business` / `impact` / `executive` |

Length-only checks are **not enough**: a model can return a long, off-topic, or refusal-style paragraph that still passes `output.length > 50`. Content assertions verify that each template still produces **SOC-relevant** language for the scenario (observables, ATT&CK framing, detection concepts, executive narrative). That is the regression signal when prompts, gateway transforms, or models change.

Do **not** broaden assertions into meaningless generic terms just to pass `tinyllama`. Prefer a small, meaningful suite over a large, diluted one.

**Why not full JSON schema checks?** `tinyllama` rarely emits valid schema-shaped JSON for these long templates. Assertions therefore check **domain keywords** rather than parseable structure. Preferred tokens (source IP, `T1110`, etc.) remain in the `contains-any` lists so stronger models or improved prompts raise the bar automatically; fallback tokens keep the suite green on this VPS without dropping quality checks entirely.

### Prompt regression testing

Re-run the same SSH failed-login case after any prompt edit, gateway change, or model swap. Failures mean a template stopped producing usable SOC language (refusals, empty/short output, or missing domain terms). That is cheaper and more repeatable than manual chat review.

### SOC and detection-engineering value

| Workflow | What the assertions protect |
| -------- | --------------------------- |
| **Triage (`alert_summary`)** | Output still references SSH-style auth-failure activity, not an unrelated or empty reply |
| **Threat framing (`mitre_mapping`)** | Output stays in MITRE ATT&CK vocabulary useful for pivots and coverage review |
| **Detection engineering (`detection_recommendation`)** | Output discusses detections/rules **and** thresholds or failed-login signals |
| **Leadership reporting (`executive_summary`)** | Output uses summary/risk and business/impact/executive language |

This is not a substitute for analyst review or red-team tooling (e.g. garak). It is a **lightweight regression gate** so prompt-library changes do not silently degrade assistant quality for SOC and detection workflows.

Interview narrative: the default suite shows operational discipline on a constrained host (4 evals, concurrency 1, Docker-only). Multi-scenario coverage is the documented next step when resources allow — not something forced by diluting assertions.

### VPS-friendly defaults

`evaluateOptions` in the config keeps load low on the 2 vCPU / 4 GB host:

- `maxConcurrency: 1` — one inference request at a time

The Compose service also enforces:

- `mem_limit: 512m`
- `cpus: "0.50"`

## Docker Compose service

The `promptfoo` service is defined in [`docker-compose.yml`](../docker-compose.yml) under the **`eval` profile**:

- Image: `ghcr.io/promptfoo/promptfoo:latest`
- Profile: `eval` (does **not** start with the default stack or the `ai` profile)
- No published ports
- Mounts: `./promptfoo` → `/config`, `./prompts` → `/prompts` (read-only)
- Working directory: `/config`
- Entrypoint: `["promptfoo"]`
- Shares the default Compose network so it can reach `ai-gateway` by service name

## Prerequisites

1. **AI profile running** — Ollama and the AI Gateway must be up:

   ```bash
   ./scripts/start-ai.sh
   ```

2. **tinyllama available** — pull if needed:

   ```bash
   docker exec ollama ollama pull tinyllama
   ```

3. **Docker only** — do **not** install Node, npm, or npx on the host.

## How to Run Evaluations

From `platform/`:

```bash
./scripts/start-ai.sh
docker compose --profile eval run --rm promptfoo eval -c /config/promptfooconfig.yaml
./scripts/stop-ai.sh
```

Optional resource monitoring in another terminal:

```bash
docker stats
```

Validate config before a run:

```bash
cd promptfoo
python3 - <<'PY'
import yaml
with open("promptfooconfig.yaml") as f:
    yaml.safe_load(f)
print("YAML valid")
PY

cd ..
docker compose --profile eval --profile ai config
```

### Quick gateway smoke test

Before running promptfoo, confirm the gateway responds (via Nginx on the host):

```bash
curl -s http://localhost/gateway/health
curl -s http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Say OK in one word."}'
```

## Why This Matters for AI Security / SOC Workflows

Security teams increasingly use LLMs to **triage alerts**, **explain suspicious activity**, and **draft detection logic**. Those outputs affect analyst trust and response speed — so they need the same engineering discipline as any other automation:

| Concern | How promptfoo helps |
| ------- | ------------------- |
| **Consistency** | Same alert template should produce usable summaries after model or gateway changes |
| **Regression** | Prompt edits or model swaps can be compared side by side |
| **Grounding** | Assertions catch empty, off-topic, or refusal-style responses before they reach analysts |
| **Audit trail** | Eval results document what was tested and when — useful for lab notes and portfolio narrative |

This is not a replacement for red-team tooling (e.g. garak) or production guardrails. It is a **lightweight quality layer** for prompt templates that will eventually power the MCP security assistant and gateway-backed SOC workflows.

## Extending the Suite

To add library tests:

1. Add a `file:///prompts/<template>.md` entry under `prompts:`.
2. Ensure the shared test `vars` include every required template input (see frontmatter in the `.md` file).
3. Keep sample inputs short — use condensed rows from [`sample_data/`](../../sample_data/) rather than full alert dumps.
4. Keep assertions meaningful; do not dilute them to paper over model weakness.
5. Prefer **one scenario at a time** on this VPS. Do not enable Defender / Proofpoint / AWS in the default active suite.
6. Re-run via Docker Compose; do not introduce host Node/npm.

## Related Documentation

- [../README.md](../README.md) — platform overview and AI Gateway
- [prompt-library.md](./prompt-library.md) — SOC prompt templates, variable contracts, and evaluation guidance
- [architecture.md](./architecture.md) — traffic flows and model defaults
- [platform-blueprint.md](./platform-blueprint.md) — roadmap (promptfoo, garak, MCP integration)
