#!/usr/bin/env python3
"""
End-to-end portfolio demo: load an alert JSON, invoke investigate_alert
via the MCP stdio server, and render a Markdown SOC investigation report.
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
_DEFAULT_ALERT = _ROOT / "sample_data" / "ssh_failed_login.json"

_QUERY_GROUP_TITLES = {
    "qradar_aql": "QRadar AQL",
    "sentinel_kql": "Microsoft Sentinel KQL",
    "defender_advanced_hunting_kql": "Microsoft Defender Advanced Hunting KQL",
    "opensearch_dql": "OpenSearch / DQL",
}


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


def _bullet_list(items: list[Any]) -> str:
    if not items:
        return "_None provided._"
    lines = []
    for item in items:
        text = str(item).strip()
        lines.append(f"- {text}" if text else "-")
    return "\n".join(lines)


def _render_mitre(mappings: Any) -> str:
    if not isinstance(mappings, list) or not mappings:
        return "_No MITRE ATT&CK mappings returned._"

    sections: list[str] = []
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        sections.append(
            "\n".join(
                [
                    f"- **Technique ID:** {mapping.get('technique_id', 'n/a')}",
                    f"- **Technique name:** {mapping.get('technique_name', 'n/a')}",
                    f"- **Tactic:** {mapping.get('tactic', 'n/a')}",
                    f"- **Confidence:** {mapping.get('confidence', 'n/a')}",
                    f"- **Rationale:** {mapping.get('rationale', 'n/a')}",
                ]
            )
        )
    return "\n\n".join(sections) if sections else "_No MITRE ATT&CK mappings returned._"


def _render_queries(recommended_queries: Any) -> str:
    if not isinstance(recommended_queries, dict) or not recommended_queries:
        return "_No recommended investigation queries returned._"

    sections: list[str] = []
    for key, queries in recommended_queries.items():
        title = _QUERY_GROUP_TITLES.get(key, key)
        sections.append(f"### {title}")
        if not isinstance(queries, list) or not queries:
            sections.append("_No queries in this group._")
            continue
        for query in queries:
            sections.append(f"```text\n{query}\n```")
    return "\n\n".join(sections)


def render_markdown_report(alert: dict[str, Any], result: dict[str, Any]) -> str:
    """Build the SOC Investigation Report Markdown from alert + tool result."""
    platform = alert.get("platform", "n/a")
    alert_type = alert.get("alert_type", "n/a")
    severity = alert.get("severity", "n/a")
    confidence = result.get("confidence", "n/a")

    summary = str(result.get("summary") or "_No executive summary returned._")
    severity_assessment = str(
        result.get("severity_assessment") or "_No severity assessment returned._"
    )

    next_steps = result.get("next_steps")
    if not isinstance(next_steps, list):
        next_steps = []

    detection = result.get("detection_opportunities")
    if not isinstance(detection, list):
        detection = []

    limitations = result.get("limitations")
    if not isinstance(limitations, list):
        limitations = []

    parts = [
        "# SOC Investigation Report",
        "",
        "## Alert Overview",
        f"- **Platform:** {platform}",
        f"- **Alert type:** {alert_type}",
        f"- **Vendor severity:** {severity}",
        f"- **Confidence:** {confidence}",
        "",
        "## Executive Summary",
        "",
        summary,
        "",
        "## Severity Assessment",
        "",
        severity_assessment,
        "",
        "## MITRE ATT&CK Mapping",
        "",
        _render_mitre(result.get("mitre")),
        "",
        "## Recommended Investigation Queries",
        "",
        _render_queries(result.get("recommended_queries")),
        "",
        "## Next Investigation Steps",
        "",
        _bullet_list(next_steps),
        "",
        "## Detection Engineering Opportunities",
        "",
        _bullet_list(detection),
        "",
        "## Analysis Limitations",
        "",
        _bullet_list(limitations),
        "",
        "---",
        "",
        "Generated by the offline SOC Investigation Tools MCP server.",
        "",
    ]
    return "\n".join(parts)


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
            "MCP stdio server, and render a Markdown SOC investigation report."
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        alert = _load_alert(args.alert_file)
        result = asyncio.run(run_investigation(alert))
        report = render_markdown_report(alert, result)

        if args.output is None:
            sys.stdout.write(report)
            if not report.endswith("\n"):
                sys.stdout.write("\n")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report, encoding="utf-8")
            print(f"Wrote report to {args.output}", file=sys.stderr)

    except (FileNotFoundError, ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — CLI: no stack traces for unexpected failures
        print(f"Error: investigation failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
