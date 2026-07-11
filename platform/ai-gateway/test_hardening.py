"""Focused unit tests for AI Gateway hardening (auth + request limits).

Run from platform/ai-gateway with GATEWAY_API_KEY set before import, e.g.:

  GATEWAY_API_KEY=test-gateway-key-not-for-production \\
  MAX_PROMPT_CHARS=100 \\
  MAX_REQUEST_BYTES=1024 \\
  python -m unittest test_hardening.py
"""

from __future__ import annotations

import importlib
import os
import unittest
from unittest.mock import AsyncMock, patch


def _load_app(
    *,
    gateway_api_key: str = "test-gateway-key-not-for-production",
    max_prompt_chars: str = "100",
    max_request_bytes: str = "1024",
):
    os.environ["GATEWAY_API_KEY"] = gateway_api_key
    os.environ["MAX_PROMPT_CHARS"] = max_prompt_chars
    os.environ["MAX_REQUEST_BYTES"] = max_request_bytes
    os.environ["DEFAULT_PROVIDER"] = "ollama"
    os.environ["DEFAULT_MODEL"] = "tinyllama"
    os.environ.pop("OPENAI_API_KEY", None)

    import main as gateway_main

    importlib.reload(gateway_main)
    return gateway_main


class GatewayHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = _load_app()
        from fastapi.testclient import TestClient

        self.client = TestClient(self.gateway.app)
        self.valid_headers = {
            "Content-Type": "application/json",
            "X-API-Key": "test-gateway-key-not-for-production",
        }

    def test_health_unauthenticated(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "healthy")
        self.assertNotIn("GATEWAY_API_KEY", str(body))
        self.assertNotIn("api_key", str(body).lower())

    def test_metrics_unauthenticated(self) -> None:
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("ai_gateway", response.text)

    def test_chat_missing_api_key(self) -> None:
        response = self.client.post(
            "/chat",
            headers={"Content-Type": "application/json"},
            json={"provider": "ollama", "model": "tinyllama", "prompt": "test"},
        )
        self.assertEqual(response.status_code, 401)

    def test_chat_invalid_api_key(self) -> None:
        response = self.client.post(
            "/chat",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "wrong-value",
            },
            json={"provider": "ollama", "model": "tinyllama", "prompt": "test"},
        )
        self.assertEqual(response.status_code, 403)

    def test_chat_gateway_key_not_configured(self) -> None:
        gateway = _load_app(gateway_api_key="")
        from fastapi.testclient import TestClient

        client = TestClient(gateway.app)
        response = client.post(
            "/chat",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "anything",
            },
            json={"provider": "ollama", "model": "tinyllama", "prompt": "test"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertIn("GATEWAY_API_KEY", response.json()["detail"])

    def test_chat_empty_prompt(self) -> None:
        response = self.client.post(
            "/chat",
            headers=self.valid_headers,
            json={"provider": "ollama", "model": "tinyllama", "prompt": "   "},
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("empty", response.json()["detail"].lower())

    def test_chat_prompt_too_large(self) -> None:
        response = self.client.post(
            "/chat",
            headers=self.valid_headers,
            json={
                "provider": "ollama",
                "model": "tinyllama",
                "prompt": "x" * 101,
            },
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn("maximum length", response.json()["detail"])

    def test_chat_request_body_too_large(self) -> None:
        oversized = "y" * 2000
        response = self.client.post(
            "/chat",
            headers=self.valid_headers,
            content=(
                b'{"provider":"ollama","model":"tinyllama","prompt":"'
                + oversized.encode()
                + b'"}'
            ),
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn("Request body", response.json()["detail"])

    def test_chat_valid_key_success(self) -> None:
        with patch.object(
            self.gateway,
            "call_ollama",
            new=AsyncMock(return_value="authenticated gateway ok"),
        ):
            response = self.client.post(
                "/chat",
                headers=self.valid_headers,
                json={
                    "provider": "ollama",
                    "model": "tinyllama",
                    "prompt": "Say only: authenticated gateway ok",
                },
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["provider"], "ollama")
        self.assertEqual(body["response"], "authenticated gateway ok")
        self.assertIn("request_id", body)
        self.assertNotIn("api_key", str(body).lower())


if __name__ == "__main__":
    unittest.main()
