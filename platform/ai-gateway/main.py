import os
import time
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from starlette.responses import Response

from metrics import record_request_metrics
from providers.ollama import call_ollama
from providers.openai_provider import call_openai
from telemetry import log_request_telemetry

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
DEFAULT_PROVIDER = os.getenv("DEFAULT_PROVIDER", "ollama")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "tinyllama")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

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


def _error_type_for_status(status_code: int, detail: str) -> str:
    if status_code == 400 and "OPENAI_API_KEY" in detail:
        return "missing_api_key"
    if status_code == 400 and "Unsupported provider" in detail:
        return "unsupported_provider"
    if status_code == 502:
        return "upstream_error"
    return "request_error"


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
async def chat(request: ChatRequest):
    request_id = str(uuid.uuid4())
    started = time.perf_counter()
    provider = (request.provider or DEFAULT_PROVIDER).lower()
    model = _resolve_model(provider, request.model)

    try:
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported provider '{provider}'. Use one of: {sorted(SUPPORTED_PROVIDERS)}",
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
        latency_ms = int((time.perf_counter() - started) * 1000)
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        error_type = _error_type_for_status(exc.status_code, detail)
        log_request_telemetry(
            request_id=request_id,
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            success=False,
            status_code=exc.status_code,
            error_type=error_type,
        )
        record_request_metrics(
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            success=False,
            status_code=exc.status_code,
            error_type=error_type,
        )
        raise
