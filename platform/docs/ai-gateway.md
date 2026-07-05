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
  providers/
    __init__.py
    ollama.py             # call_ollama(prompt, model, base_url)
    openai_provider.py    # call_openai(prompt, model, api_key)
```

`main.py` reads environment variables, validates the request, selects the provider, measures latency, and returns the normalized JSON contract. Each provider module owns only its upstream API call and error translation.

This separation keeps the gateway thin at the HTTP layer and makes new backends a matter of adding a module plus a routing branch — without touching Ollama or OpenAI code that already works. Future providers (DeepSeek, Claude, Gemini, Azure OpenAI) would follow the same pattern: implement `call_<provider>(prompt, model, …)` with credentials passed in from `main.py`, register the provider name in routing, and leave the client `/chat` contract unchanged.

Secrets remain environment-only: `main.py` reads `OPENAI_API_KEY` from the container env and passes it into `call_openai`; provider modules never log keys or read `.env` files directly.

## Provider routing

All generation goes through one endpoint:

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/health` | GET | Gateway status and defaults (no secrets) |
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
  "provider": "ollama",
  "model": "tinyllama",
  "response": "...",
  "latency_ms": 1234
}
```

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
- **No key leakage in logs** — The gateway does not log the API key. Missing-key errors describe configuration, not secret values.
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
- **Observability hooks** — Normalized responses include `latency_ms` for SLO tracking and cost/latency comparisons across providers.
- **Security engineering mindset** — Fail closed on missing keys, no secret logging, `.env` hygiene, and documentation of trust boundaries.
