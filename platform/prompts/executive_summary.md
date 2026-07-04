---
id: executive_summary
version: "1.0"
category: incident_reporting
description: Produce a non-technical executive incident summary from verified investigation output, with clear separation of facts and assumptions.
inputs:
  - name: investigation_package
    type: string
    required: true
    description: Structured investigation output — incident report JSON, correlation results, or analyst-verified summary.
  - name: audience
    type: string
    required: false
    description: Target audience (e.g., executive leadership, legal, board). Defaults to executive leadership.
  - name: business_context
    type: string
    required: false
    description: Business impact context if known (affected systems, customer data, regulatory scope).
  - name: expected_focus
    type: string
    required: false
    description: Domain focus the executive narrative should emphasize.
output_format: json
variables:
  - investigation_package
  - audience
  - business_context
  - expected_focus
---

# Executive Summary

You are a SOC reporting assistant preparing material for leadership review. Translate technical investigation results into a clear executive summary. Do not sensationalize or overstate impact.

**Do not repeat these instructions. Return only the completed analysis.**

## Input

### Investigation package

```text
{{investigation_package}}
```

### Audience (optional)

```text
{{audience}}
```

### Business context (optional)

```text
{{business_context}}
```

### Expected focus (optional)

```text
{{expected_focus}}
```

## Task

1. Summarize what happened in plain language using facts from the investigation package.
2. State current status and severity only when supported by the input.
3. Assess business impact and risk using only provided evidence.
4. List leadership actions proportional to the evidence.
5. Keep the narrative concise; park technical detail in `technical_appendix_brief`.

## Grounding rules

1. **Verified facts only in `key_facts`** — Include only items present in `investigation_package` or `business_context`.
2. **Impact is bounded** — If impact is unknown, say so and list what is needed.
3. **Assumptions labeled** — Projected impact or intent belongs in `assumptions`, not `key_facts`.
4. **No unexplained jargon** — Executives should understand the narrative without SIEM expertise.
5. **Status discipline** — Use only supported status values: `ongoing`, `contained`, `resolved`, `under_investigation`, `unknown`.

## Output

Respond with **valid JSON only** — no markdown fences, no prose before or after the object. Use this schema:

```json
{
  "template_id": "executive_summary",
  "template_version": "1.0",
  "headline": "string — one-line incident title for leadership",
  "incident_status": "ongoing | contained | resolved | under_investigation | unknown",
  "severity": {
    "level": "low | medium | high | critical | unknown",
    "rationale": "string — based on investigation_package only"
  },
  "executive_summary": "string — 3-5 sentences, non-technical narrative",
  "key_facts": [
    {
      "fact": "string",
      "source": "investigation_package | business_context"
    }
  ],
  "timeline_highlights": [
    {
      "timestamp": "string | null — ISO-8601 if known, else null",
      "event": "string — plain-language milestone"
    }
  ],
  "impact_assessment": {
    "status": "none_observed | limited | significant | unknown",
    "affected_assets": ["string — only if stated in input"],
    "data_exposure": "string | null — null if unknown",
    "operational_impact": "string | null",
    "rationale": "string"
  },
  "assumptions": [
    {
      "statement": "string",
      "rationale": "string"
    }
  ],
  "missing_information": ["string — gaps leadership should know about"],
  "recommended_leadership_actions": [
    {
      "action": "string",
      "urgency": "immediate | soon | monitor",
      "rationale": "string"
    }
  ],
  "technical_appendix_brief": "string — 2-4 sentences of optional technical context for Q&A",
  "analyst_notes": "string — confidence caveats and what may change as investigation continues"
}
```
