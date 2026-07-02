# AI SOC Analyst Prompt Library

Reusable prompt templates for Security Operations Center (SOC) workflows. Templates live in [`prompts/`](../prompts/) and are designed for analyst-facing AI assistance, gateway-backed inference, and future MCP tool integration.

For AI Gateway API details, see [../README.md](../README.md#ai-gateway). For prompt regression testing, see [promptfoo.md](./promptfoo.md).

## Why Prompt Engineering Matters

SOC teams use LLMs to triage alerts, explain suspicious activity, map threats to MITRE ATT&CK, draft detections, and brief leadership. Without deliberate prompt design, models tend to:

- **Hallucinate** observables, timelines, or threat intel not present in the alert
- **Blend fact and inference**, making analyst review harder and increasing escalation errors
- **Drift** when models or gateways change, breaking workflows that once "felt fine" in chat

Prompt engineering treats analyst-facing templates as **versioned interfaces** — same discipline as detection rules or runbooks. Each template in this library enforces:

| Principle | How templates enforce it |
| --------- | ------------------------ |
| Structured output | JSON schemas with required sections |
| Grounding | Rules that limit `observations` to input-derived facts |
| Explicit uncertainty | Separate `assumptions`, `missing_information`, and confidence fields |
| Analyst safety | No containment commands or claims of deployed detections without evidence |

This library is the **content layer** above the AI Gateway. The gateway routes inference; prompts define *what* the model should do and *how* outputs must be shaped.

## How Prompts Are Organized

```text
platform/prompts/
├── alert_summary.md           # Triage summary from raw or normalized alerts
├── mitre_mapping.md           # Evidence-linked ATT&CK technique mapping
├── detection_recommendation.md # Detection gaps and rule concepts from findings
└── executive_summary.md       # Leadership-facing incident narrative
```

### Template anatomy

Every file follows the same structure:

1. **YAML frontmatter** — Machine-readable metadata for future loaders and MCP tools:
   - `id`, `version`, `category`, `description`
   - `inputs` — named parameters with types and required flags
   - `variables` — placeholder names substituted at render time
   - `output_format` — currently `json` for all templates

2. **Role and grounding rules** — Analyst context plus non-negotiable constraints (no invented telemetry, assumptions labeled).

3. **Variable blocks** — `{{variable_name}}` placeholders filled by callers.

4. **Output schema** — JSON shape the model must return; suitable for parsing, validation, and ticket systems.

### Template catalog

| ID | File | SOC use case | Primary inputs |
| -- | ---- | ------------ | -------------- |
| `alert_summary` | [alert_summary.md](../prompts/alert_summary.md) | Tier-1/2 triage handoff | `alert_data`, optional `investigation_context` |
| `mitre_mapping` | [mitre_mapping.md](../prompts/mitre_mapping.md) | Threat framing and hunt pivots | `activity_description`, optional platform and MITRE hints |
| `detection_recommendation` | [detection_recommendation.md](../prompts/detection_recommendation.md) | Post-investigation detection engineering | `investigation_findings`, optional alert type and environment |
| `executive_summary` | [executive_summary.md](../prompts/executive_summary.md) | Leadership briefing | `investigation_package`, optional audience and business context |

### Rendering a template (conceptual)

Callers replace `{{variables}}` with runtime values, then send the full document as the `prompt` body to the gateway:

```text
1. Load platform/prompts/alert_summary.md
2. Substitute {{alert_data}} with JSON or log text
3. POST /gateway/chat with the rendered prompt
4. Parse JSON response; validate against expected schema
```

No gateway changes are required today — substitution can be done in shell scripts, Python, promptfoo, or future MCP tools.

Example using sample lab data:

```bash
# Render manually (illustrative)
ALERT=$(cat sample_data/wazuh_alert.json)
sed "s|{{alert_data}}|$ALERT|g; s|{{investigation_context}}||g" \
  platform/prompts/alert_summary.md | \
  curl -s http://localhost/gateway/chat \
    -H "Content-Type: application/json" \
    -d @-  # in practice, wrap as {"prompt": "<rendered text>"}
```

For production use, prefer a small renderer that handles JSON escaping and omits optional sections cleanly.

## Integration with the AI Gateway

The [AI Gateway](../ai-gateway/main.py) exposes a single generation endpoint suitable for prompt library use:

```text
POST http://<host>/gateway/chat
Content-Type: application/json

{
  "model": "tinyllama",
  "prompt": "<rendered template text>"
}
```

Response field `response` contains model text. Callers should:

1. **Render** the template with case-specific variables.
2. **Send** the full prompt via `/gateway/chat` (default model `tinyllama`; override with `"model": "gemma2:2b"` when quality matters more than speed).
3. **Parse** JSON from `response` (strip accidental markdown fences if the model adds them).
4. **Validate** required keys and reject or re-prompt on malformed output.

```text
┌─────────────────┐     ┌──────────────────┐     ┌─────────┐
│ Prompt template │────▶│ Render + variables│────▶│ Gateway │
│ (prompts/*.md)  │     │ (caller / script) │     │ /chat   │
└─────────────────┘     └──────────────────┘     └────┬────┘
                                                        │
                                                        ▼
                                               ┌────────────────┐
                                               │ Structured JSON │
                                               │ for analysts /  │
                                               │ tickets / MCP   │
                                               └────────────────┘
```

**Not in scope yet (by design):** gateway-side template registry, automatic variable injection, or MCP tool wiring. Those layers will consume this library without changing template content.

### Suggested workflow chain

Typical SOC progression using multiple templates:

```text
Alert JSON
    → alert_summary
    → mitre_mapping (activity from summary observations)
    → detection_recommendation (findings + techniques)
    → executive_summary (full investigation package)
```

Each step should pass **structured prior output** forward rather than re-sending raw alerts alone, so later prompts inherit verified observations.

## Evaluating Prompts with Promptfoo

[promptfoo](https://www.promptfoo.dev/) runs repeatable evaluations against the gateway. Existing config: [`promptfoo/promptfooconfig.yaml`](../promptfoo/promptfooconfig.yaml). See [promptfoo.md](./promptfoo.md) for prerequisites and VPS-friendly run settings.

### Connecting library templates to promptfoo

1. **Reference prompts by file** — Add entries under `prompts:` that load rendered templates, or inline a shortened eval variant that preserves grounding rules and output schema.

2. **Use test variables** — Map `vars` to template placeholders (`alert_data`, `investigation_findings`, etc.). Lab sample data works well:
   - [`sample_data/wazuh_alert.json`](../../sample_data/wazuh_alert.json)
   - [`sample_data/command_execution_alert.json`](../../sample_data/command_execution_alert.json)

3. **Assert on structure and keywords** — For local models (`tinyllama`), prefer:
   - `icontains` / `icontains-any` for security concepts (SSH, MITRE IDs, detection)
   - `is-json` when the model reliably returns parseable JSON
   - `javascript` assertions to check `observations` vs `assumptions` keys exist

Example test sketch for `alert_summary` (add to `promptfooconfig.yaml` when extending the suite):

```yaml
tests:
  - description: alert_summary template — SSH failure grounding
    vars:
      alert_data: |
        {"rule":{"id":"5710","level":8},"srcip":"192.168.1.50","user":"root",
         "full_log":"Failed password for root from 192.168.1.50"}
      investigation_context: ""
    assert:
      - type: icontains-any
        value: ["observations", "assumptions", "192.168.1.50", "root"]
      - type: icontains-any
        value: ["ssh", "authentication", "failed", "password"]
```

### What to measure over time

| Metric | Why it matters |
| ------ | -------------- |
| Schema compliance | Can downstream tools parse the response? |
| Grounding | Do outputs cite input facts vs invent new IPs or users? |
| Regression | Does a model swap change triage quality? |
| Latency | CPU-only VPS inference stays usable with short prompts |

Run evaluations after prompt edits, model changes, or gateway updates:

```bash
./platform/scripts/start-ai.sh
cd platform/promptfoo && npx promptfoo@latest eval
```

## Future MCP Integration (planned)

MCP tools in `scripts/soc_mcp_server.py` already produce deterministic structured output. The prompt library complements them:

- **MCP tools** — Bounded Python logic, no model hallucination risk
- **Prompt templates** — Flexible narrative and reasoning when a model is appropriate

A future integration might expose tools such as `render_soc_prompt` or `analyze_alert_with_template` that load `platform/prompts/*.md`, substitute variables from investigation state, call the gateway, and return validated JSON. **No MCP or gateway changes are included in this module** — templates are authored now so that integration has a stable contract.

## Related Documentation

- [../README.md](../README.md) — Platform overview and AI Gateway
- [promptfoo.md](./promptfoo.md) — Evaluation setup and run instructions
- [architecture.md](./architecture.md) — Gateway placement in the stack
- [../prompts/](../prompts/) — Template source files
