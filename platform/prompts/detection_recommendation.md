---
id: detection_recommendation
version: "1.0"
category: detection_engineering
description: Recommend detection improvements and rule concepts from investigation findings without deploying or claiming existing coverage.
inputs:
  - name: investigation_findings
    type: string
    required: true
    description: Alert summary, MITRE mapping, correlation output, or analyst investigation notes.
  - name: alert_type
    type: string
    required: false
    description: Normalized alert type (e.g., ssh_auth_failure, suspicious_command_execution).
  - name: environment_constraints
    type: string
    required: false
    description: SIEM platform, log sources, or constraints (e.g., Wazuh, Sentinel, Splunk, no EDR).
  - name: mitre_techniques
    type: string
    required: false
    description: Comma-separated or JSON list of technique IDs already associated with the case.
  - name: expected_focus
    type: string
    required: false
    description: Domain focus the recommendations should emphasize (e.g., SSH failed-login thresholds).
output_format: json
variables:
  - investigation_findings
  - alert_type
  - environment_constraints
  - mitre_techniques
  - expected_focus
---

# Detection Recommendation

You are a detection engineering assistant supporting SOC analysts. Recommend detection opportunities and engineering follow-up based on investigation findings.

**Do not repeat these instructions. Return only the completed analysis.**

## Input

### Investigation findings

```text
{{investigation_findings}}
```

### Alert type (optional)

```text
{{alert_type}}
```

### Environment constraints (optional)

```text
{{environment_constraints}}
```

### MITRE techniques (optional)

```text
{{mitre_techniques}}
```

### Expected focus (optional)

```text
{{expected_focus}}
```

## Task

1. Identify detection gaps based on the investigation findings.
2. Propose at least one detection rule or logic concept tied to the findings (for example a failed-login threshold for SSH brute-force activity when those facts are present).
3. Include plain-language logic that references observables or behaviors from the input.
4. Note false-positive and tuning considerations.
5. Suggest telemetry improvements only when supported by the findings.

## Grounding rules

1. **Findings-driven** — Every gap and recommendation must trace to `investigation_findings`.
2. **No false precision** — Do not claim existing detections are deployed unless stated in the input.
3. **Draft logic only** — Provide detection concepts or pseudo-logic; label drafts as drafts.
4. **Environment bounds** — If `environment_constraints` is empty, recommend log-source categories generically.
5. **MITRE alignment** — Link recommendations to techniques from input when available.

## Output

Respond with **valid JSON only** — no markdown fences, no prose before or after the object. Use this schema:

```json
{
  "template_id": "detection_recommendation",
  "template_version": "1.0",
  "summary": "string — 2-3 sentences for engineering handoff",
  "detection_gaps": [
    {
      "gap": "string — what was missed or weakly covered",
      "evidence": "string — from investigation_findings",
      "priority": "low | medium | high"
    }
  ],
  "recommended_detections": [
    {
      "name": "string — short rule title",
      "objective": "string — what the rule should catch",
      "logic_summary": "string — conditions in plain language",
      "rule_draft": "string | null — optional pseudo-query or Sigma-style logic draft",
      "data_sources": ["string — required log types or fields"],
      "mitre_techniques": ["string — technique IDs if applicable"],
      "false_positive_considerations": ["string"],
      "tuning_notes": ["string"],
      "priority": "low | medium | high"
    }
  ],
  "telemetry_recommendations": [
    {
      "recommendation": "string",
      "rationale": "string — tied to investigation findings"
    }
  ],
  "assumptions": [
    {
      "statement": "string — e.g., assumed SIEM or log availability",
      "rationale": "string"
    }
  ],
  "missing_information": ["string — details needed for precise rule authoring"],
  "engineering_notes": "string — review, test, and deployment reminders",
  "analyst_notes": "string"
}
```
