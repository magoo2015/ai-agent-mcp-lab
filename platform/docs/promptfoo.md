# Promptfoo Evaluation

This document describes the [promptfoo](https://www.promptfoo.dev/) setup for the AI Security Engineering Platform: what it does, how to run evaluations against the AI Gateway through Docker, and why prompt regression testing matters for SOC and detection-engineering workflows.

For gateway API details, see [../README.md](../README.md#ai-gateway). For prompt template design and variable contracts, see [prompt-library.md](./prompt-library.md). For architecture context, see [architecture.md](./architecture.md).

## Design principles

- **Docker only** — Promptfoo runs in a container so the VPS host does **not** need Node, npm, or npx.
- **Dev/eval tooling, not runtime** — Promptfoo is evaluation tooling. It is not part of the always-on platform (Nginx, Open WebUI, Grafana, Prometheus, Ollama, AI Gateway).
- **Resource limits** — The Compose service caps memory and CPU so eval jobs cannot starve the small VPS (2 vCPU / 4 GB RAM).
- **Low concurrency** — `maxConcurrency: 1` prevents multiple simultaneous model calls.
- **tinyllama only** — Day-to-day evals use `tinyllama`. `gemma2:2b` is too heavy for routine evaluation on this host.
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

**Assertions:** Tests use lightweight checks suitable for a small local model:

- `not-contains` for refusal phrases (`I cannot`, `I'm unable`)
- `javascript` length check (`output.length > 50`)

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
4. Keep assertions lenient for `tinyllama`; tighten only when a stronger model is intentionally used.
5. Re-run via Docker Compose; do not introduce host Node/npm.

## Related Documentation

- [../README.md](../README.md) — platform overview and AI Gateway
- [prompt-library.md](./prompt-library.md) — SOC prompt templates, variable contracts, and evaluation guidance
- [architecture.md](./architecture.md) — traffic flows and model defaults
- [platform-blueprint.md](./platform-blueprint.md) — roadmap (promptfoo, garak, MCP integration)
