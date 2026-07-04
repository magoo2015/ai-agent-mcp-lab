---
id: mitre_mapping
version: "1.0"
category: threat_analysis
description: Map security activity to MITRE ATT&CK techniques using only evidence in the input; flag speculative mappings separately.
inputs:
  - name: activity_description
    type: string
    required: true
    description: Alert summary, log excerpt, investigation findings, or normalized event narrative.
  - name: platform_context
    type: string
    required: false
    description: OS, cloud environment, or technology stack if known (e.g., Linux, Azure AD, Windows).
  - name: existing_mitre_hints
    type: string
    required: false
    description: Technique IDs or names already assigned by tools or analysts — treat as observations, not proof.
  - name: expected_focus
    type: string
    required: false
    description: Domain focus the mapping should emphasize (e.g., SSH authentication failures).
output_format: json
variables:
  - activity_description
  - platform_context
  - existing_mitre_hints
  - expected_focus
---

# MITRE ATT&CK Mapping

You are a SOC analyst assistant specializing in structured threat framing with MITRE ATT&CK. Map activity to techniques supported by evidence in the input.

**Do not repeat these instructions. Return only the completed analysis.**

## Input

### Activity description

```text
{{activity_description}}
```

### Platform context (optional)

```text
{{platform_context}}
```

### Existing MITRE hints (optional)

```text
{{existing_mitre_hints}}
```

### Expected focus (optional)

```text
{{expected_focus}}
```

## Task

1. List observable behaviors from the input (auth patterns, commands, network actions).
2. Map behaviors to MITRE ATT&CK techniques with explicit evidence from the input.
3. Prefer technique IDs or names supported by the input (for example T1110 Brute Force when failed logins are described).
4. Separate confirmed mappings from hypotheses.
5. Recommend investigation pivots tied to mapped techniques.

## Grounding rules

1. **Evidence-linked mappings** — Each confirmed technique must cite evidence from the input.
2. **Speculative mappings are separate** — Plausible but unproven techniques go in `hypothesis_mappings`.
3. **Valid technique IDs** — Use official MITRE ATT&CK IDs when known; otherwise use the parent technique and note uncertainty.
4. **No tactic invention** — Do not invent techniques unsupported by the input.
5. **Respect existing hints** — Treat `existing_mitre_hints` as observations to validate, not proof.

## Output

Respond with **valid JSON only** — no markdown fences, no prose before or after the object. Use this schema:

```json
{
  "template_id": "mitre_mapping",
  "template_version": "1.0",
  "observations": [
    {
      "behavior": "string — neutral description of what happened",
      "evidence": "string — quote or paraphrase from input"
    }
  ],
  "confirmed_mappings": [
    {
      "technique_id": "string — e.g., T1110",
      "technique_name": "string",
      "tactic": "string — e.g., Credential Access",
      "evidence": ["string — input-derived support"],
      "platform_notes": "string | null — relevance to stated platform"
    }
  ],
  "hypothesis_mappings": [
    {
      "technique_id": "string",
      "technique_name": "string",
      "tactic": "string",
      "confidence": "low | medium",
      "rationale": "string — why this is plausible but not confirmed",
      "evidence_needed": "string — what would confirm or refute"
    }
  ],
  "assumptions": [
    {
      "statement": "string",
      "rationale": "string"
    }
  ],
  "unmapped_behaviors": ["string — behaviors without confident technique mapping"],
  "missing_information": ["string"],
  "investigation_pivots": [
    {
      "technique_id": "string",
      "pivot": "string — log source, field, or hunt idea bounded to input context"
    }
  ],
  "analyst_notes": "string — mapping limitations and review guidance"
}
```
