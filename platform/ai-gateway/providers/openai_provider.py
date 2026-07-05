import httpx
from fastapi import HTTPException

OPENAI_API_URL = "https://api.openai.com/v1/responses"


def _extract_response_text(data: dict) -> str:
    if text := data.get("output_text"):
        return text

    parts: list[str] = []
    for item in data.get("output", []):
        if item.get("type") == "message":
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    parts.append(content.get("text", ""))
        elif item.get("type") == "output_text":
            parts.append(item.get("text", ""))
    return "".join(parts)


async def call_openai(prompt: str, model: str, api_key: str) -> str:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                OPENAI_API_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "input": prompt,
                },
                timeout=300.0,
            )
            response.raise_for_status()
            data = response.json()
            text = _extract_response_text(data)
            if not text:
                raise HTTPException(
                    status_code=502,
                    detail="OpenAI returned an empty response",
                )
            return text
        except httpx.HTTPStatusError as exc:
            detail = "OpenAI request failed"
            try:
                error_body = exc.response.json()
                if isinstance(error_body.get("error"), dict):
                    detail = error_body["error"].get("message", detail)
            except ValueError:
                pass
            raise HTTPException(
                status_code=502, detail=f"OpenAI error: {detail}"
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502, detail=f"Failed to reach OpenAI: {exc}"
            ) from exc
