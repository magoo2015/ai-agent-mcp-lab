#!/usr/bin/env python3
"""
SOC Investigation Tools — MCP stdio server (v1).

Exposes the existing offline SOC framework over the official Python MCP SDK.
stdout is reserved exclusively for MCP JSON-RPC; all logs go to stderr.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Optional

# Ensure package root is on sys.path when run as a script.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mcp.server.fastmcp import FastMCP

from schemas.alert_schema import AlertInput, AlertObservables, MitreMapping
from tools.investigate_alert import investigate_alert as run_investigate_alert
from tools.mitre_mapper import map_alert_to_mitre
from tools.query_generator import generate_queries as run_generate_queries

# ---------------------------------------------------------------------------
# Logging — stderr only (stdout is MCP protocol)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("soc-investigation-tools")

mcp = FastMCP("soc-investigation-tools")


def _normalize_query_output(queries: dict[str, list[str]]) -> dict[str, list[str]]:
    """Ensure a stable schema with all supported query-language keys."""
    return {
        "qradar_aql": queries.get("qradar_aql", []),
        "sentinel_kql": queries.get("sentinel_kql", []),
        "defender_advanced_hunting_kql": queries.get("defender_advanced_hunting_kql", []),
        "opensearch_dql": queries.get("opensearch_dql", []),
    }


@mcp.tool()
def investigate_alert(alert: AlertInput) -> dict[str, Any]:
    """
    Investigate a structured security alert offline.

    Returns an analyst-ready investigation package with summary, severity
    assessment, MITRE mappings, recommended queries, next steps, detection
    opportunities, confidence, and limitations. Does not call live SIEM/EDR APIs.
    """
    logger.info(
        "investigate_alert called platform=%s alert_type=%s severity=%s",
        alert.platform,
        alert.alert_type,
        alert.severity,
    )
    result = run_investigate_alert(alert)
    return result.model_dump()


@mcp.tool()
def map_mitre(
    alert_type: str,
    description: str,
    observables: Optional[AlertObservables] = None,
) -> dict[str, Any]:
    """
    Map an alert type to a deterministic MITRE ATT&CK technique.

    Offline rule-based mapping only — not threat-intel enriched.
    Returns technique_id, technique_name, tactic, confidence, and rationale.
    """
    logger.info("map_mitre called alert_type=%s", alert_type)
    alert = AlertInput(
        platform="offline",
        alert_type=alert_type,
        severity="unknown",
        description=description,
        observables=observables or AlertObservables(),
    )
    mappings = map_alert_to_mitre(alert)
    primary: MitreMapping = mappings[0]
    return primary.model_dump()


@mcp.tool()
def generate_queries(
    observables: AlertObservables,
    alert_type: str,
    platform: str = "offline",
    severity: str = "unknown",
    description: str = "",
) -> dict[str, list[str]]:
    """
    Generate offline example investigation pivots for common SIEM/EDR languages.

    Returns qradar_aql, sentinel_kql, defender_advanced_hunting_kql, and
    opensearch_dql templates. These are illustrative pivots, not live queries.
    """
    logger.info("generate_queries called alert_type=%s", alert_type)
    alert = AlertInput(
        platform=platform,
        alert_type=alert_type,
        severity=severity,
        description=description or f"Query generation for {alert_type}",
        observables=observables,
    )
    return _normalize_query_output(run_generate_queries(alert))


def main() -> None:
    logger.info("Starting MCP server soc-investigation-tools (stdio transport)")
    # Default transport is stdio; do not print banners to stdout.
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
