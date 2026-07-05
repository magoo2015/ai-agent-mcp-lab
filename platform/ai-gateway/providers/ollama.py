import httpx
from fastapi import HTTPException


async def call_ollama(prompt: str, model: str, base_url: str) -> str:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=300.0,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502, detail=f"Failed to reach Ollama: {exc}"
            ) from exc
