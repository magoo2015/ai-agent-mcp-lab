# Promptfoo Evaluation

This document describes the [promptfoo](https://www.promptfoo.dev/) setup for the AI Security Engineering Platform: what it does, how to run evaluations against the AI Gateway, and why prompt regression testing matters for SOC and detection-engineering workflows.

For gateway API details, see [../README.md](../README.md#ai-gateway). For prompt template design and variable contracts, see [prompt-library.md](./prompt-library.md). For architecture context, see [architecture.md](./architecture.md).

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
| [`promptfoo/promptfooconfig.yaml`](../promptfoo/promptfooconfig.yaml) | Provider, prompts, tests, and VPS-friendly rate limits |

The HTTP provider posts to:

```text
POST http://nginx/gateway/chat
Content-Type: application/json

{"model": "tinyllama", "prompt": "<eval prompt>"}
```

The gateway response field `response` is extracted via `transformResponse: json.response`.

### Prompt library evaluation

The config evaluates the **AI SOC Analyst Prompt Library** in [`prompts/`](../prompts/). Each library template is loaded as a promptfoo prompt via `file://` and bound to a dedicated test case:

| Prompt file | Test focus | Sample input |
| ----------- | ---------- | ------------ |
| [`alert_summary.md`](../prompts/alert_summary.md) | Structured triage JSON from raw alert | Condensed [`wazuh_alert.json`](../../sample_data/wazuh_alert.json) (rule 5710 SSH failure) |
| [`mitre_mapping.md`](../prompts/mitre_mapping.md) | Evidence-linked ATT&CK mapping | Activity narrative derived from the same Wazuh alert |
| [`detection_recommendation.md`](../prompts/detection_recommendation.md) | Detection gaps and rule concepts | Investigation findings from the SSH auth failure case |
| [`executive_summary.md`](../prompts/executive_summary.md) | Leadership briefing JSON | Compact investigation package built from alert fields |

**How rendering works:** promptfoo substitutes `{{variable}}` placeholders in each `.md` template using `vars` from the matching test (e.g. `alert_data`, `activity_description`, `investigation_package`). The full rendered document — including grounding rules and output schema — is sent to `/gateway/chat`.

**Per-test prompt binding:** Library tests set `prompts: [<label>]` so each case runs only against its template. Three legacy generic SOC smoke tests use the `generic-soc` inline prompt for quick gateway checks.

**Assertions:** Library tests combine:

- `icontains-any` on **JSON schema field names** (`observations`, `confirmed_mappings`, `recommended_detections`, `executive_summary`, etc.)
- `icontains-any` on **input-derived facts** (IPs, users, rule IDs, SSH/auth keywords)
- `javascript` checks that attempt `JSON.parse` and fall back to regex for JSON-like structure when `tinyllama` wraps output in fences or mixes prose

This is intentionally lenient for a small local model while still catching empty, off-topic, or schema-stripped responses.

### Generic smoke tests

Three short, CPU-friendly SOC scenarios exercise the gateway without loading library templates:

| Test | Scenario |
| ---- | -------- |
| SOC alert summary | Summarize a failed SSH authentication alert (Wazuh-style) |
| Suspicious SSH login | Explain why an off-hours login from an unusual IP is suspicious |
| Detection engineering | Recommend a Sigma-style rule for `curl \| bash` execution |

Assertions use `icontains-any` keyword checks — appropriate for a small local model where outputs vary, but should still mention relevant security concepts.

### VPS-friendly defaults

`evaluateOptions` in the config keeps load low on the 2 vCPU / 4GB host:

- `maxConcurrency: 1` — one inference request at a time
- `delay: 2000` — two-second pause between requests

With seven test cases (three generic + four library), a full eval takes roughly 14+ seconds of delay alone, plus inference time. Override from the CLI if needed: `promptfoo eval -j 1 --delay 3000`.

## Prerequisites

1. **AI profile running** — Ollama and the AI Gateway must be up:

   ```bash
   ./platform/scripts/start-ai.sh
   ```

2. **tinyllama available** — pull via Open WebUI or `docker exec ollama ollama pull tinyllama` if not already installed.

3. **Node.js** — promptfoo runs via `npx` (no project `package.json` required).

4. **Network reachability** — the eval runner must reach the gateway:
   - From the **VPS host**: `http://localhost/gateway/chat`
   - From a **container on the Docker network**: `http://nginx/gateway/chat` (default in config)

## How to Run Evaluations

From the repository root:

```bash
cd platform/promptfoo
npx promptfoo@latest eval
```

Run only prompt library tests (skip generic smoke tests):

```bash
npx promptfoo@latest eval --filter-pattern "alert_summary|mitre_mapping|detection_recommendation|executive_summary"
```

View the interactive report:

```bash
npx promptfoo@latest view
```

### Running from the VPS host

The default provider URL (`http://nginx/gateway/chat`) resolves inside the Docker network. From the host, override the provider URL:

```bash
cd platform/promptfoo
npx promptfoo@latest eval --providers '[{"id":"http://localhost/gateway/chat","label":"ai-gateway-tinyllama","config":{"method":"POST","headers":{"Content-Type":"application/json"},"body":{"model":"tinyllama","prompt":"{{prompt}}"},"transformResponse":"json.response"}}]'
```

Or temporarily edit `promptfooconfig.yaml` to use `http://localhost/gateway/chat`.

### Running inside Docker (optional)

To use the default `http://nginx/gateway/chat` URL without edits, run promptfoo on the same Compose network:

```bash
docker run --rm -it \
  --network ai-security-platform_default \
  -v "$(pwd)/platform/promptfoo:/config" \
  -v "$(pwd)/platform/prompts:/prompts" \
  -w /config \
  node:22-slim \
  sh -c "npx promptfoo@latest eval"
```

Adjust the network name if your Compose project name differs (`docker network ls`). `file://../prompts/*.md` resolves to `/prompts` when the working directory is `/config`.

### Quick gateway smoke test

Before running promptfoo, confirm the gateway responds:

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
| **Regression** | Prompt edits or model swaps (e.g. `tinyllama` → `gemma2:2b`) can be compared side by side |
| **Grounding** | Assertions catch empty, off-topic, or missing-keyword responses before they reach analysts |
| **Schema compliance** | Library tests check for expected JSON sections and field names from [`prompts/`](../prompts/) |
| **Audit trail** | Eval results document what was tested and when — useful for lab notes and portfolio narrative |

This is not a replacement for red-team tooling (e.g. garak) or production guardrails. It is a **lightweight quality layer** for prompt templates that will eventually power the MCP security assistant and gateway-backed SOC workflows.

## Extending the Suite

To add library tests:

1. Add a `file://../prompts/<template>.md` entry under `prompts:` with a unique `label`.
2. Append a test with matching `prompts: [<label>]` and `vars` for every required template input (see frontmatter in the `.md` file).
3. Keep sample inputs short — use condensed rows from [`sample_data/`](../../sample_data/) rather than full alert dumps.
4. Assert on **schema field names** plus **input-derived keywords**; use `javascript` for lenient JSON parsing with regex fallback.
5. Re-run `promptfoo eval` and commit config changes; eval artifacts in `.promptfoo/` are local output and need not be committed.

To add generic smoke tests, append under `tests:` with `prompts: [generic-soc]` and an `input` var.

## Related Documentation

- [../README.md](../README.md) — platform overview and AI Gateway
- [prompt-library.md](./prompt-library.md) — SOC prompt templates, variable contracts, and evaluation guidance
- [architecture.md](./architecture.md) — traffic flows and model defaults
- [platform-blueprint.md](./platform-blueprint.md) — roadmap (promptfoo, garak, MCP integration)
