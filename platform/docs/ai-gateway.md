# AI Gateway

The AI Gateway is a lightweight FastAPI service that sits between platform clients and LLM backends. It exposes a single stable `/chat` contract while routing internally to local Ollama or cloud OpenAI based on the `provider` field.

For broader platform context, see [architecture.md](./architecture.md). For prompt regression testing through the gateway, see [promptfoo.md](./promptfoo.md).

## Architecture

```text
Client (curl, promptfoo, MCP tool, automation)
    │
    ▼
POST /chat  ──►  AI Gateway (:8000)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   provider=ollama         provider=openai
        │                       │
        ▼                       ▼
 Ollama /api/generate    OpenAI /v1/responses
 (local, Docker network)  (HTTPS, bearer token)
```

Clients never call Ollama or OpenAI directly. Nginx can expose the gateway at `/gateway/` on port 80; during development the gateway also publishes host port **8000** for direct testing.

## Provider abstraction

Provider-specific HTTP logic lives in `platform/ai-gateway/providers/`, not in `main.py`:

```text
platform/ai-gateway/
  main.py                 # routing, env, validation, latency, response shape
  telemetry.py            # safe structured JSON request logging (metadata only)
  metrics.py              # Prometheus counters/histograms (low-cardinality labels)
  providers/
    __init__.py
    ollama.py             # call_ollama(prompt, model, base_url)
    openai_provider.py    # call_openai(prompt, model, api_key)
```

`main.py` reads environment variables, validates the request, selects the provider, measures latency, emits telemetry, and returns the normalized JSON contract. Each provider module owns only its upstream API call and error translation. `telemetry.py` writes one JSON object per `/chat` request to stdout — metadata only, never prompt or secret content.

This separation keeps the gateway thin at the HTTP layer and makes new backends a matter of adding a module plus a routing branch — without touching Ollama or OpenAI code that already works. Future providers (DeepSeek, Claude, Gemini, Azure OpenAI) would follow the same pattern: implement `call_<provider>(prompt, model, …)` with credentials passed in from `main.py`, register the provider name in routing, and leave the client `/chat` contract unchanged.

Secrets remain environment-only: `main.py` reads `OPENAI_API_KEY` from the container env and passes it into `call_openai`; provider modules never log keys or read `.env` files directly.

## Provider routing

All generation goes through one endpoint:

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/health` | GET | Gateway status and defaults (no secrets) |
| `/metrics` | GET | Prometheus exposition format (request counters, latency histogram, errors) |
| `/models` | GET | Lists models from Ollama `/api/tags` |
| `/chat` | POST | Generate a response with provider routing |

### Request body

```json
{
  "prompt": "Summarize this alert...",
  "model": "tinyllama",
  "provider": "ollama"
}
```

```json
{
  "prompt": "Summarize this alert...",
  "model": "gpt-4.1-mini",
  "provider": "openai"
}
```

| Field | Required | Default | Notes |
| ----- | -------- | ------- | ----- |
| `prompt` | yes | — | User or system prompt text |
| `provider` | no | `DEFAULT_PROVIDER` (`ollama`) | `ollama` or `openai` |
| `model` | no | `DEFAULT_MODEL` (Ollama) or `OPENAI_MODEL` (OpenAI) | Provider-specific model id |

### Normalized response

Both providers return the same shape:

```json
{
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "provider": "ollama",
  "model": "tinyllama",
  "response": "...",
  "latency_ms": 1234
}
```

`request_id` is a UUID generated per request. Clients can correlate gateway responses with container logs using this id.

## Request telemetry

Every `/chat` request emits **one structured JSON line** to stdout (visible via `docker logs ai-gateway`). This is metadata-only observability — not a full request/response audit log.

### Telemetry fields

| Field | Type | Description |
| ----- | ---- | ----------- |
| `request_id` | string | UUID for this request; matches the `/chat` response |
| `timestamp_utc` | string | ISO-8601 UTC timestamp when the log line was written |
| `provider` | string | `ollama` or `openai` |
| `model` | string | Model id used for the request |
| `latency_ms` | integer | End-to-end gateway latency for the request |
| `success` | boolean | `true` if the gateway returned 200; `false` otherwise |
| `status_code` | integer | HTTP status returned to the client (200, 400, 502, …) |
| `error_type` | string | Present on failure only — e.g. `missing_api_key`, `unsupported_provider`, `upstream_error` |

Example success log:

```json
{"request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "timestamp_utc": "2026-07-05T17:22:01.123456+00:00", "provider": "ollama", "model": "tinyllama", "latency_ms": 842, "success": true, "status_code": 200}
```

Example failure log (missing OpenAI key):

```json
{"request_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "timestamp_utc": "2026-07-05T17:22:05.654321+00:00", "provider": "openai", "model": "gpt-4.1-mini", "latency_ms": 1, "success": false, "status_code": 400, "error_type": "missing_api_key"}
```

### Why prompts are not logged by default

Security and privacy drive the default:

- **Prompts may contain alerts, PII, or credentials** — SOC workflows often send raw alert JSON or incident details in the prompt. Logging that content duplicates sensitive data into log stores with broader access than the inference path.
- **API keys must never appear in logs** — `OPENAI_API_KEY` is read from the environment only; telemetry never includes keys, bearer tokens, or upstream auth headers.
- **Upstream bodies are excluded** — Full Ollama/OpenAI response payloads are not logged; only success/failure metadata and classified `error_type` are recorded.

This is a deliberate **security/privacy tradeoff**: you gain request-level observability (volume, latency, error rates per provider) without building a prompt archive. When deeper debugging is needed, use `request_id` to correlate a client response with logs, then reproduce with a controlled test prompt — or enable optional prompt logging behind an explicit feature flag in a future phase (not v1).

## Prometheus metrics

The gateway exposes a **`GET /metrics`** endpoint in [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/). Metrics are updated on every `/chat` request alongside stdout JSON telemetry.

### Metric names

| Metric | Type | Labels | Description |
| ------ | ---- | ------ | ----------- |
| `ai_gateway_requests_total` | Counter | `provider`, `model`, `status` | Total `/chat` requests by HTTP status code |
| `ai_gateway_request_latency_seconds` | Histogram | `provider`, `model` | End-to-end gateway latency in seconds |
| `ai_gateway_errors_total` | Counter | `provider`, `model`, `error_type` | Failed requests by classified error type |

Example series after traffic:

```text
ai_gateway_requests_total{provider="ollama",model="tinyllama",status="200"} 3
ai_gateway_request_latency_seconds_bucket{provider="ollama",model="tinyllama",le="1.0"} 2
ai_gateway_errors_total{provider="openai",model="gpt-4.1-mini",error_type="missing_api_key"} 1
```

### Label choices (low cardinality)

Labels are limited to values with a **small, bounded set** of possible values:

| Label | Values | Why |
| ----- | ------ | --- |
| `provider` | `ollama`, `openai` | Fixed provider registry |
| `model` | e.g. `tinyllama`, `gpt-4.1-mini` | Small set of configured models — not free-form user input as unbounded labels |
| `status` | HTTP status codes (`200`, `400`, `502`, …) | Bounded set of gateway response codes |
| `error_type` | `missing_api_key`, `unsupported_provider`, `upstream_error`, `request_error` | Classified error buckets from `_error_type_for_status()` |

### Why prompts and request_ids are not labels

Prometheus labels become **time-series dimensions**. Every unique label combination creates a new series. High-cardinality labels cause:

- **Memory explosion** in Prometheus TSDB
- **Slow queries** and dashboard timeouts
- **Privacy leakage** — prompts may contain alert text, PII, or credentials; `request_id` is per-request and would create one series per call

Prompts belong in optional, gated audit logs (future), not in metrics. Per-request correlation uses `request_id` in **JSON telemetry** and the `/chat` response body — not Prometheus labels.

### Path to Grafana dashboards

With Prometheus scraping `ai-gateway:8000` (see [`prometheus/prometheus.yml`](../prometheus/prometheus.yml)), Grafana can visualize:

- **Request rate** — `rate(ai_gateway_requests_total[5m])` by `provider`
- **Error rate** — `rate(ai_gateway_errors_total[5m])` by `error_type`
- **Latency percentiles** — `histogram_quantile(0.95, rate(ai_gateway_request_latency_seconds_bucket[5m]))` by `provider`
- **SLO panels** — success ratio: requests with `status="200"` vs total

Stdout JSON telemetry remains useful for **per-request drill-down** (find a `request_id`, check logs); Prometheus metrics power **aggregated SRE dashboards** and future alerting.

### Security / privacy tradeoffs

| Approach | Benefit | Cost |
| -------- | ------- | ---- |
| Metadata-only metrics | Safe to scrape, store, and share with SRE | No per-prompt visibility |
| Low-cardinality labels | Stable Prometheus performance | Cannot slice by user, IP, or alert ID |
| No auth on `/metrics` (v1) | Simple lab setup | Endpoint should not be public in production |

Authentication for `/metrics` is deferred to a later phase. In production, restrict scrape to the internal Docker network or protect with network policy / reverse-proxy auth.

### Testing metrics

```bash
curl -s http://localhost:8000/metrics | grep ai_gateway
```

Generate traffic first (see [Testing Ollama](#testing-ollama) and [Testing OpenAI later](#testing-openai-later)).

Verify Prometheus scrape (from a host with access to the Prometheus API, or via `docker exec`):

```bash
docker exec prometheus wget -qO- http://localhost:9090/api/v1/targets | grep ai-gateway
```

### Path to Prometheus and Grafana (telemetry → metrics)

Stdout JSON lines are the first observability layer; **Prometheus metrics (v1)** add the second:

1. ~~**Export counters and histograms**~~ — `GET /metrics` on the gateway; Prometheus scrapes `ai-gateway:8000`.
2. **Dashboard in Grafana** — Provider latency comparison, error rate by `error_type`, and SLO panels using PromQL over the series above.
3. **Optional log shipping** — Promtail or Fluent Bit can still tail stdout JSON for per-request `request_id` correlation.

Because the metrics schema is stable and secret-free, adding dashboards does not require changing what clients send or widening the trust boundary.

## Environment variables

Configure in `platform/.env` (copy from `.env.example`). Docker Compose passes these into the `ai-gateway` container via `env_file` and `environment` interpolation.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Ollama API base URL inside Docker |
| `DEFAULT_PROVIDER` | `ollama` | Provider when request omits `provider` |
| `DEFAULT_MODEL` | `tinyllama` | Ollama model when request omits `model` |
| `OPENAI_MODEL` | `gpt-4.1-mini` | OpenAI model when `provider=openai` and request omits `model` |
| `OPENAI_API_KEY` | *(unset)* | Bearer token for OpenAI; **never commit** |

## Why API keys stay in the gateway

- **Single secret boundary** — Only the gateway container needs `OPENAI_API_KEY`. Browsers, promptfoo configs, and MCP clients send prompts without credentials.
- **No key leakage in logs** — The gateway does not log the API key, prompt text, or raw upstream response bodies. Telemetry records metadata only (`request_id`, provider, model, latency, status).
- **Provider abstraction** — Callers use one JSON contract; switching from local to cloud is a `provider` field, not a client rewrite.
- **Audit and rate control (future)** — Central routing enables request logging, allowlists, and per-tenant quotas without changing every client.

OpenAI integration uses the [Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses) (`POST /v1/responses`) rather than legacy Chat Completions, matching OpenAI’s current recommended path for new integrations.

## Testing Ollama

Start the AI profile:

```bash
cd platform
./scripts/start-ai.sh
```

Health check:

```bash
curl -s http://localhost:8000/health
```

Chat via local Ollama:

```bash
curl -s http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"provider":"ollama","model":"tinyllama","prompt":"Say only: gateway ollama ok"}'
```

Via Nginx (when core stack is running):

```bash
curl -s http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Hello"}'
```

Omitting `provider` and `model` uses `DEFAULT_PROVIDER` and `DEFAULT_MODEL`.

## Testing OpenAI later

1. Copy `platform/.env.example` to `platform/.env` if you have not already.
2. Set a real key: `OPENAI_API_KEY=sk-...` in `.env` only.
3. Restart the gateway: `docker compose --profile ai up -d --build ai-gateway`
4. Call:

```bash
curl -s http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"provider":"openai","model":"gpt-4.1-mini","prompt":"Say only: gateway openai ok"}'
```

If `OPENAI_API_KEY` is missing, the gateway returns **400** with a clear message and does not expose secret placeholders.

## Security notes

- `.env` is listed in the repository `.gitignore`; never commit API keys.
- Use placeholder values in `.env.example` only (`OPENAI_API_KEY=replace_me`).
- API keys are read once in `main.py` from the environment and passed into provider functions; provider modules do not log or persist secrets.
- OpenAI errors from upstream are surfaced as **502** with message text only — not raw HTTP bodies containing auth headers.
- The gateway runs on the internal Docker network; host port 8000 is for lab testing — restrict or remove in production if not needed.

## Interview value

This gateway demonstrates patterns common in production AI platforms:

- **Backend-for-frontend / API gateway** — Stable client contract over swappable inference backends.
- **Secret isolation** — Cloud credentials confined to one service; clients stay credential-free.
- **Multi-provider routing** — Same API for on-prem (Ollama) and SaaS (OpenAI) with explicit `provider` selection.
- **Observability hooks** — Normalized responses include `request_id` and `latency_ms`; stdout JSON telemetry enables per-request tracing without logging prompts or secrets; Prometheus metrics expose aggregated counters and latency histograms for SRE dashboards.
- **Security engineering mindset** — Fail closed on missing keys, no secret logging, `.env` hygiene, and documentation of trust boundaries.
