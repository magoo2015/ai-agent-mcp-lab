#!/usr/bin/env python3
"""
End-to-end portfolio demo: load an alert JSON, invoke investigate_alert
via the MCP stdio server, build a structured InvestigationReport, and
render Markdown and optional standalone HTML investigation reports.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from reports.builder import build_investigation_report  # noqa: E402
from reports.html_renderer import render_html  # noqa: E402
from reports.markdown_renderer import render_markdown  # noqa: E402
from schemas.alert_schema import AlertInput, InvestigationOutput  # noqa: E402

_DEFAULT_ALERT = _ROOT / "sample_data" / "ssh_failed_login.json"


def _extract_payload(result: types.CallToolResult) -> dict[str, Any]:
    """Prefer structuredContent; fall back to parsing TextContent JSON."""
    if result.isError:
        messages = []
        for block in result.content:
            if isinstance(block, types.TextContent):
                messages.append(block.text)
        raise RuntimeError(
            "investigate_alert returned an error: " + ("; ".join(messages) or "unknown")
        )

    if result.structuredContent and isinstance(result.structuredContent, dict):
        return result.structuredContent

    for block in result.content:
        if isinstance(block, types.TextContent):
            try:
                parsed = json.loads(block.text)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"investigate_alert TextContent was not valid JSON: {exc}"
                ) from None
            if not isinstance(parsed, dict):
                raise RuntimeError(
                    "investigate_alert TextContent JSON must be an object"
                )
            return parsed

    raise RuntimeError("investigate_alert returned no parseable content")


def _load_alert(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Alert file not found: {path}")

    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in alert file {path}: {exc}") from None

    if not isinstance(data, dict):
        raise ValueError(
            f"Alert file {path} must contain a top-level JSON object, "
            f"got {type(data).__name__}"
        )
    return data


async def run_investigation(alert: dict[str, Any]) -> dict[str, Any]:
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(_ROOT / "mcp_server.py")],
        cwd=str(_ROOT),
    )

    print("Starting MCP server (stdio) and calling investigate_alert...", file=sys.stderr)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("MCP session initialized.", file=sys.stderr)

            result = await session.call_tool(
                "investigate_alert",
                arguments={"alert": alert},
            )
            payload = _extract_payload(result)
            print("Investigation complete.", file=sys.stderr)
            return payload


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Load a normalized alert JSON, invoke investigate_alert via the "
            "MCP stdio server, and render a Markdown SOC investigation report. "
            "Optionally write a standalone HTML report from the same object."
        )
    )
    parser.add_argument(
        "alert_file",
        nargs="?",
        type=Path,
        default=_DEFAULT_ALERT,
        help=(
            "Path to normalized alert JSON "
            f"(default: {_DEFAULT_ALERT.relative_to(_ROOT)})"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write the Markdown report to this file instead of stdout.",
    )
    parser.add_argument(
        "--html-output",
        type=Path,
        default=None,
        help=(
            "Write a standalone HTML investigation report to this path "
            "(UTF-8). Uses the same InvestigationReport as Markdown."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        alert_payload = _load_alert(args.alert_file)
        result_payload = asyncio.run(run_investigation(alert_payload))

        alert = AlertInput.model_validate(alert_payload)
        output = InvestigationOutput.model_validate(result_payload)
        report = build_investigation_report(alert, output)
        markdown = render_markdown(report)

        if args.output is None:
            sys.stdout.write(markdown)
            if not markdown.endswith("\n"):
                sys.stdout.write("\n")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(markdown, encoding="utf-8")
            print(f"Wrote report to {args.output}", file=sys.stderr)

        if args.html_output is not None:
            html = render_html(report)
            args.html_output.parent.mkdir(parents=True, exist_ok=True)
            args.html_output.write_text(html, encoding="utf-8")
            print(f"Wrote HTML report to {args.html_output}", file=sys.stderr)

    except (FileNotFoundError, ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — CLI: no stack traces for unexpected failures
        print(f"Error: investigation failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
