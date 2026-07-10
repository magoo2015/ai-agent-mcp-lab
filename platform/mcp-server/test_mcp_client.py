#!/usr/bin/env python3
"""
Lightweight MCP client test for soc-investigation-tools (stdio).

Launches mcp_server.py as a subprocess, lists tools, and invokes
investigate_alert with the SSH sample alert.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp import types

_ROOT = Path(__file__).resolve().parent
_SAMPLE = _ROOT / "sample_data" / "ssh_failed_login.json"
_REQUIRED_TOOLS = {"investigate_alert", "map_mitre", "generate_queries"}


def _extract_payload(result: types.CallToolResult) -> dict:
    """Prefer structuredContent; fall back to parsing text JSON."""
    if result.isError:
        messages = []
        for block in result.content:
            if isinstance(block, types.TextContent):
                messages.append(block.text)
        raise RuntimeError("investigate_alert returned an error: " + "; ".join(messages))

    if result.structuredContent and isinstance(result.structuredContent, dict):
        return result.structuredContent

    for block in result.content:
        if isinstance(block, types.TextContent):
            return json.loads(block.text)

    raise RuntimeError("investigate_alert returned no parseable content")


async def run_tests() -> None:
    if not _SAMPLE.is_file():
        raise FileNotFoundError(f"Sample alert not found: {_SAMPLE}")

    with _SAMPLE.open(encoding="utf-8") as handle:
        alert_payload = json.load(handle)

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(_ROOT / "mcp_server.py")],
        cwd=str(_ROOT),
    )

    print("MCP SDK client test — connecting to mcp_server.py via stdio...")

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("Session initialized.")

            tools_response = await session.list_tools()
            tool_names = sorted(t.name for t in tools_response.tools)
            print(f"Tools listed ({len(tool_names)}): {tool_names}")

            missing = _REQUIRED_TOOLS - set(tool_names)
            if missing:
                raise AssertionError(f"Missing required tools: {sorted(missing)}")
            print("Required tools present: investigate_alert, map_mitre, generate_queries")

            result = await session.call_tool(
                "investigate_alert",
                arguments={"alert": alert_payload},
            )
            payload = _extract_payload(result)

            summary = payload.get("summary", "")
            mitre = payload.get("mitre") or []
            technique_ids = [m.get("technique_id") for m in mitre if isinstance(m, dict)]
            recommended_queries = payload.get("recommended_queries")
            limitations = payload.get("limitations")

            print("--- investigate_alert result summary ---")
            print(f"summary: {summary[:160]}{'...' if len(summary) > 160 else ''}")
            print(f"technique_ids: {technique_ids}")
            print(
                "recommended_queries keys: "
                f"{sorted(recommended_queries.keys()) if isinstance(recommended_queries, dict) else recommended_queries}"
            )
            print(
                f"limitations count: {len(limitations) if isinstance(limitations, list) else 'n/a'}"
            )
            print(f"confidence: {payload.get('confidence')}")

            errors: list[str] = []
            if not summary:
                errors.append("missing summary")
            if "T1110" not in technique_ids:
                errors.append(f"expected T1110 in mitre, got {technique_ids}")
            if not isinstance(recommended_queries, dict) or not recommended_queries:
                errors.append("missing recommended_queries")
            if not isinstance(limitations, list) or not limitations:
                errors.append("missing limitations")

            if errors:
                raise AssertionError("Verification failed: " + "; ".join(errors))

            print("All MCP transport checks passed.")


def main() -> int:
    try:
        asyncio.run(run_tests())
    except Exception as exc:  # noqa: BLE001 — surface test failures clearly
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
