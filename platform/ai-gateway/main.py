import os
import secrets
import time
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from starlette.responses import JSONResponse, Response

from metrics import record_request_metrics
from providers.ollama import call_ollama
from providers.openai_provider import call_openai
from telemetry import log_request_telemetry

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
DEFAULT_PROVIDER = os.getenv("DEFAULT_PROVIDER", "ollama")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "tinyllama")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GATEWAY_API_KEY = os.getenv("GATEWAY_API_KEY", "")
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "12000"))
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "65536"))

SUPPORTED_PROVIDERS = {"ollama", "openai"}

app = FastAPI(
    title="AI Gateway",
    description="Lightweight gateway with Ollama and OpenAI provider routing",
)


class ChatRequest(BaseModel):
    prompt: str
    model: Optional[str] = None
    provider: Optional[str] = None


def _resolve_model(provider: str, request_model: Optional[str]) -> str:
    if request_model:
        return request_model
    if provider == "openai":
        return OPENAI_MODEL
    return DEFAULT_MODEL


def _api_keys_match(provided: str, expected: str) -> bool:
    """Constant-time comparison; unequal lengths never compare as equal."""
    if len(provided) != len(expected):
        return False
    return secrets.compare_digest(provided, expected)


def _error_type_for_status(status_code: int, detail: str) -> str:
    if status_code == 401:
        return "missing_gateway_api_key"
    if status_code == 403:
        return "invalid_gateway_api_key"
    if status_code == 503 and "GATEWAY_API_KEY" in detail:
        return "gateway_api_key_not_configured"
    if status_code == 413 and "Request body" in detail:
        return "request_body_too_large"
    if status_code in (413, 422) and "Prompt exceeds" in detail:
        return "prompt_too_large"
    if status_code == 422 and "empty" in detail.lower():
        return "empty_prompt"
    if status_code == 400 and "OPENAI_API_KEY" in detail:
        return "missing_api_key"
    if status_code == 400 and "Unsupported provider" in detail:
        return "unsupported_provider"
    if status_code == 502:
        return "upstream_error"
    return "request_error"


def _record_failure(
    *,
    request_id: str,
    provider: str,
    model: str,
    started: float,
    status_code: int,
    error_type: str,
) -> None:
    latency_ms = int((time.perf_counter() - started) * 1000)
    log_request_telemetry(
        request_id=request_id,
        provider=provider,
        model=model,
        latency_ms=latency_ms,
        success=False,
        status_code=status_code,
        error_type=error_type,
    )
    record_request_metrics(
        provider=provider,
        model=model,
        latency_ms=latency_ms,
        success=False,
        status_code=status_code,
        error_type=error_type,
    )


def _require_gateway_api_key(x_api_key: Optional[str]) -> None:
    if not GATEWAY_API_KEY:
        raise HTTPException(
            status_code=503,
            detail=(
                "Gateway API key not configured. "
                "Set GATEWAY_API_KEY in the gateway environment."
            ),
        )
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key header",
        )
    if not _api_keys_match(x_api_key, GATEWAY_API_KEY):
        raise HTTPException(
            status_code=403,
            detail="Invalid X-API-Key",
        )


def _validate_prompt(prompt: str) -> None:
    if not prompt or not prompt.strip():
        raise HTTPException(
            status_code=422,
            detail="Prompt must not be empty",
        )
    if len(prompt) > MAX_PROMPT_CHARS:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Prompt exceeds maximum length of {MAX_PROMPT_CHARS} characters"
            ),
        )


@app.middleware("http")
async def limit_request_body_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                length = -1
            if length > MAX_REQUEST_BYTES:
                request_id = str(uuid.uuid4())
                _record_failure(
                    request_id=request_id,
                    provider="unknown",
                    model="unknown",
                    started=time.perf_counter(),
                    status_code=413,
                    error_type="request_body_too_large",
                )
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": (
                            f"Request body exceeds maximum of "
                            f"{MAX_REQUEST_BYTES} bytes"
                        )
                    },
                )
    return await call_next(request)


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "default_provider": DEFAULT_PROVIDER,
        "default_model": DEFAULT_MODEL,
    }


@app.get("/models")
async def models():
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=30.0)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502, detail=f"Failed to reach Ollama: {exc}"
            ) from exc


@app.post("/chat")
async def chat(
    request: ChatRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    request_id = str(uuid.uuid4())
    started = time.perf_counter()
    provider = (request.provider or DEFAULT_PROVIDER).lower()
    model = _resolve_model(provider, request.model)

    try:
        _require_gateway_api_key(x_api_key)
        _validate_prompt(request.prompt)

        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unsupported provider '{provider}'. "
                    f"Use one of: {sorted(SUPPORTED_PROVIDERS)}"
                ),
            )

        if provider == "ollama":
            response_text = await call_ollama(request.prompt, model, OLLAMA_BASE_URL)
        else:
            if not OPENAI_API_KEY:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "OpenAI provider requested but OPENAI_API_KEY is not configured. "
                        "Set OPENAI_API_KEY in the gateway environment."
                    ),
                )
            response_text = await call_openai(request.prompt, model, OPENAI_API_KEY)

        latency_ms = int((time.perf_counter() - started) * 1000)
        log_request_telemetry(
            request_id=request_id,
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            success=True,
            status_code=200,
        )
        record_request_metrics(
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            success=True,
            status_code=200,
        )
        return {
            "request_id": request_id,
            "provider": provider,
            "model": model,
            "response": response_text,
            "latency_ms": latency_ms,
        }
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        error_type = _error_type_for_status(exc.status_code, detail)
        _record_failure(
            request_id=request_id,
            provider=provider,
            model=model,
            started=started,
            status_code=exc.status_code,
            error_type=error_type,
        )
        raise
