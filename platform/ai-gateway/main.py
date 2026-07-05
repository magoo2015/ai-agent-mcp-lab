import os
import time
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from providers.ollama import call_ollama
from providers.openai_provider import call_openai

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
    provider = (request.provider or DEFAULT_PROVIDER).lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider '{provider}'. Use one of: {sorted(SUPPORTED_PROVIDERS)}",
        )

    if provider == "openai":
        model = request.model or OPENAI_MODEL
    else:
        model = request.model or DEFAULT_MODEL

    started = time.perf_counter()
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

    return {
        "provider": provider,
        "model": model,
        "response": response_text,
        "latency_ms": latency_ms,
    }
