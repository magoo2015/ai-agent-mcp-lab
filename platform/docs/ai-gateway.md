# AI Gateway

The AI Gateway is a lightweight FastAPI service that sits between platform clients and LLM backends. It exposes a single stable `/chat` contract while routing internally to local Ollama or cloud OpenAI based on the `provider` field.

For broader platform context, see [architecture.md](./architecture.md). For prompt regression testing through the gateway, see [promptfoo.md](./promptfoo.md).

## Trust boundary (Hardening v1)

```text
Public / lab host
    │
    ▼
Nginx :80  ──►  /gateway/*  (only public path to the gateway)
    │
    ▼
AI Gateway :8000  (Docker network only — no host port published)
    │
    ├── GET  /health   — unauthenticated (liveness for ops / Nginx checks)
    ├── GET  /metrics  — unauthenticated, internal scrape only (not proxied by Nginx)
    └── POST /chat     — requires X-API-Key; size-limited
```

**Nginx is the only host entry point** for the gateway. Direct host access to port **8000** was removed so the gateway is not reachable from the public internet without going through Nginx. Prometheus continues to scrape `http://ai-gateway:8000/metrics` on the Docker network.

This is **lab hardening**, not a full production security posture. HTTPS/TLS Hardening v1 is prepared in **bootstrap mode**, but traffic remains HTTP until a public hostname passes DNS/firewall validation and a certificate is issued. There is no separate auth service, no Redis session store, and no database-backed identity. See [tls.md](./tls.md).

## Architecture

```text
Client (curl, automation)
    │  X-API-Key (required for /chat)
    ▼
Nginx :80 /gateway/
    │
    ▼
POST /chat  ──►  AI Gateway (:8000, internal)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   provider=ollama         provider=openai
        │                       │
        ▼                       ▼
 Ollama /api/generate    OpenAI /v1/responses
 (local, Docker network)  (HTTPS, bearer token)
```

Clients never call Ollama or OpenAI directly. During bootstrap, external callers use `http://<host>/gateway/...` only. After certificate activation, Nginx will redirect that path to `https://<domain>/gateway/...`.

## Provider abstraction

Provider-specific HTTP logic lives in `platform/ai-gateway/providers/`, not in `main.py`:

```text
platform/ai-gateway/
  main.py                 # routing, auth, limits, validation, latency, response shape
  telemetry.py            # safe structured JSON request logging (metadata only)
  metrics.py              # Prometheus counters/histograms (low-cardinality labels)
  providers/
    __init__.py
    ollama.py             # call_ollama(prompt, model, base_url)
    openai_provider.py    # call_openai(prompt, model, api_key)
```

`main.py` reads environment variables, enforces gateway API-key auth on `/chat`, applies prompt/body limits, selects the provider, measures latency, emits telemetry, and returns the normalized JSON contract. Each provider module owns only its upstream API call and error translation. `telemetry.py` writes one JSON object per `/chat` request to stdout — metadata only, never prompt or secret content.

Secrets remain environment-only: `GATEWAY_API_KEY` and `OPENAI_API_KEY` are read from the container env. Provider modules never log keys or read `.env` files directly.

## Access control

| Endpoint | Auth | Exposure |
| -------- | ---- | -------- |
| `GET /health` | None | Via Nginx `/gateway/health` (public on port 80 in this lab) |
| `GET /metrics` | None | **Internal Docker network only** — not proxied by Nginx |
| `POST /chat` | `X-API-Key` header | Via Nginx `/gateway/chat` |
| `GET /models` | None (lab) | Via Nginx `/gateway/models` |

### Why `/health` is public

Liveness checks and simple ops probes should work without distributing the gateway key. `/health` returns only status and default provider/model names — never secrets.

### Why `/metrics` is internal only

Prometheus scrapes `ai-gateway:8000` on the Docker network. Nginx does **not** expose `/metrics`. Leaving scrape unauthenticated is acceptable for this lab because the port is not published on the host; production would add network policy or scrape auth later.

Nginx explicitly returns 404 for public `/metrics`, `/metrics/`, and paths beginning `/gateway/metrics`; the generic `/gateway/` proxy must not make the scrape endpoint public.

### `X-API-Key` behavior for `POST /chat`

| Condition | HTTP status |
| --------- | ----------- |
| Missing `X-API-Key` header | **401** |
| Invalid `X-API-Key` | **403** |
| `GATEWAY_API_KEY` unset in gateway env | **503** (fail closed) |

Validation uses constant-time comparison (`secrets.compare_digest`). The configured key is never logged, returned in responses, included in telemetry, or exposed via `/health` or `/metrics`.

```bash
curl -s http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-local-gateway-key>" \
  -d '{"provider":"ollama","model":"tinyllama","prompt":"Hello"}'
```

## Request limits

| Variable | Default | Effect |
| -------- | ------- | ------ |
| `MAX_PROMPT_CHARS` | `12000` | Reject prompts longer than this (HTTP **413**) |
| `MAX_REQUEST_BYTES` | `65536` | Reject bodies larger than this via middleware (HTTP **413**) |

Additional prompt rules:

- Empty / whitespace-only prompts → HTTP **422**
- Nginx `client_max_body_size 64k` on `/gateway/` aligns with the gateway byte limit

Rejected oversized bodies are not logged; telemetry records metadata and a classified `error_type` only.

## Provider routing

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/health` | GET | Gateway status and defaults (no secrets) |
| `/metrics` | GET | Prometheus exposition format (internal scrape) |
| `/models` | GET | Lists models from Ollama `/api/tags` |
| `/chat` | POST | Generate a response with provider routing (API key required) |

### Request body

```json
{
  "prompt": "Summarize this alert...",
  "model": "tinyllama",
  "provider": "ollama"
}
```

| Field | Required | Default | Notes |
| ----- | -------- | ------- | ----- |
| `prompt` | yes | — | Non-empty; max `MAX_PROMPT_CHARS` |
| `provider` | no | `DEFAULT_PROVIDER` (`ollama`) | `ollama` or `openai` |
| `model` | no | `DEFAULT_MODEL` (Ollama) or `OPENAI_MODEL` (OpenAI) | Provider-specific model id |

### Normalized response

```json
{
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "provider": "ollama",
  "model": "tinyllama",
  "response": "...",
  "latency_ms": 1234
}
```

## Request telemetry

Every `/chat` request (including auth and validation failures) emits **one structured JSON line** to stdout (visible via `docker logs ai-gateway`). Metadata only — not a full request/response audit log.

### Telemetry fields

| Field | Type | Description |
| ----- | ---- | ----------- |
| `request_id` | string | UUID for this request |
| `timestamp_utc` | string | ISO-8601 UTC timestamp |
| `provider` | string | `ollama`, `openai`, or `unknown` (pre-parse rejections) |
| `model` | string | Model id or `unknown` |
| `latency_ms` | integer | End-to-end gateway latency |
| `success` | boolean | `true` if HTTP 200 |
| `status_code` | integer | HTTP status returned |
| `error_type` | string | Present on failure only |

Classified `error_type` values (Hardening v1):

| `error_type` | When |
| ------------ | ---- |
| `missing_gateway_api_key` | No `X-API-Key` header |
| `invalid_gateway_api_key` | Wrong key |
| `gateway_api_key_not_configured` | Env key unset (503) |
| `empty_prompt` | Blank prompt |
| `prompt_too_large` | Prompt over `MAX_PROMPT_CHARS` |
| `request_body_too_large` | Body over `MAX_REQUEST_BYTES` |
| `missing_api_key` | OpenAI provider without `OPENAI_API_KEY` |
| `unsupported_provider` | Unknown provider name |
| `upstream_error` | Ollama/OpenAI upstream failure |

Example success log:

```json
{"request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "timestamp_utc": "2026-07-05T17:22:01.123456+00:00", "provider": "ollama", "model": "tinyllama", "latency_ms": 842, "success": true, "status_code": 200}
```

Example auth failure (no key value present):

```json
{"request_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "timestamp_utc": "2026-07-05T17:22:05.654321+00:00", "provider": "ollama", "model": "tinyllama", "latency_ms": 1, "success": false, "status_code": 401, "error_type": "missing_gateway_api_key"}
```

### Why API keys and prompts are not logged

- **Prompts may contain alerts, PII, or credentials** — logging them duplicates sensitive data into broader log stores.
- **Gateway and OpenAI keys must never appear in logs** — keys are env-only; telemetry never includes header values or bearer tokens.
- **Rejected bodies are not logged** — size rejections record `error_type` only.

## Prometheus metrics

`GET /metrics` remains on the gateway for internal scrape. Metrics update on every `/chat` attempt alongside stdout JSON telemetry.

| Metric | Type | Labels |
| ------ | ---- | ------ |
| `ai_gateway_requests_total` | Counter | `provider`, `model`, `status` |
| `ai_gateway_request_latency_seconds` | Histogram | `provider`, `model` |
| `ai_gateway_errors_total` | Counter | `provider`, `model`, `error_type` |

### Testing metrics (internal)

Prometheus scrapes `http://ai-gateway:8000/metrics` on the Docker network. Confirm via target health / PromQL (some Prometheus image `wget` builds mishandle `hostname:port`):

```bash
docker exec prometheus wget -qO- http://localhost:9090/api/v1/targets | grep ai-gateway
docker exec prometheus wget -qO- 'http://localhost:9090/api/v1/query?query=ai_gateway_requests_total'
```

Do **not** expect `http://localhost:8000/metrics` to work — host port 8000 is closed.

## Environment variables

Configure in `platform/.env` (copy from `.env.example`). Never commit real keys.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Ollama API base URL inside Docker |
| `DEFAULT_PROVIDER` | `ollama` | Provider when request omits `provider` |
| `DEFAULT_MODEL` | `tinyllama` | Ollama model when request omits `model` |
| `OPENAI_MODEL` | `gpt-4.1-mini` | OpenAI model default |
| `OPENAI_API_KEY` | *(unset)* | OpenAI bearer token; **never commit** |
| `GATEWAY_API_KEY` | *(unset)* | Required for `/chat`; fail closed if missing |
| `MAX_PROMPT_CHARS` | `12000` | Max prompt length |
| `MAX_REQUEST_BYTES` | `65536` | Max raw request body size |

## Why API keys stay in the gateway

- **Single secret boundary** — Only the gateway needs `OPENAI_API_KEY` and `GATEWAY_API_KEY`.
- **No key leakage in logs** — Telemetry records metadata only.
- **Provider abstraction** — Callers use one JSON contract.
- **Fail closed** — Missing gateway key returns 503 for `/chat` rather than open access.

## Testing (via Nginx)

Start the AI profile:

```bash
cd platform
./scripts/start-ai.sh
# or: docker compose --profile ai up -d --build ai-gateway nginx prometheus
```

Ensure `platform/.env` contains a local `GATEWAY_API_KEY` (not committed).

Health (no key):

```bash
curl -i http://localhost/gateway/health
```

Chat without key → **401**:

```bash
curl -i http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -d '{"provider":"ollama","model":"tinyllama","prompt":"test"}'
```

Chat with valid key → **200**:

```bash
curl -i http://localhost/gateway/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-local-gateway-key>" \
  -d '{"provider":"ollama","model":"tinyllama","prompt":"Say only: authenticated gateway ok"}'
```

Confirm host port 8000 is closed:

```bash
curl -i http://localhost:8000/health   # should fail / connection refused
docker ps --filter name=ai-gateway    # must not show 0.0.0.0:8000->8000/tcp
```

## Testing OpenAI later

1. Set `OPENAI_API_KEY` and `GATEWAY_API_KEY` in `platform/.env` only.
2. Restart: `docker compose --profile ai up -d --build ai-gateway`
3. Call via Nginx with both the gateway key header and `provider=openai`.

## Security notes

- `.env` is gitignored; never commit API keys.
- Use placeholders in `.env.example` only.
- Host port **8000** is not published; Nginx is the only public entry point.
- `/metrics` is not exposed through Nginx.
- HTTP remains active during TLS bootstrap. Port 443, redirects, and HTTPS security headers are not active until a trusted certificate exists.
- Gateway API-key enforcement is unchanged by TLS preparation.
- Unit coverage for auth/limits: `platform/ai-gateway/test_hardening.py`.

## Interview value

- **Trust boundary reduction** — Remove direct service ports; force a single reverse-proxy path.
- **Fail-closed API auth** — Shared gateway key with constant-time compare before inference.
- **Defense in depth** — Prompt and body size limits at app and proxy layers.
- **Safe observability** — Classified errors without logging secrets or prompt content.
