import os
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "tinyllama")

app = FastAPI(title="AI Gateway", description="Lightweight gateway for Ollama")


class ChatRequest(BaseModel):
    model: Optional[str] = None
    prompt: str


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ai-gateway"}


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
    model_used = request.model or DEFAULT_MODEL
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": model_used,
                    "prompt": request.prompt,
                    "stream": False,
                },
                timeout=300.0,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "model": data.get("model", model_used),
                "model_used": model_used,
                "response": data.get("response", ""),
            }
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502, detail=f"Failed to reach Ollama: {exc}"
            ) from exc
