#!/usr/bin/env python3
"""Offline MCP SOC Tool Framework — CLI entry point (v1)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure package root is on sys.path when run as a script.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from schemas.alert_schema import AlertInput  # noqa: E402
from tools.investigate_alert import investigate_alert  # noqa: E402


def load_alert(path: Path) -> AlertInput:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return AlertInput.model_validate(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Investigate a structured security alert (offline v1 CLI)."
    )
    parser.add_argument(
        "alert_file",
        type=Path,
        help="Path to structured alert JSON (e.g., sample_data/ssh_failed_login.json)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON instead of pretty-printed output.",
    )
    args = parser.parse_args(argv)

    if not args.alert_file.is_file():
        print(f"Error: alert file not found: {args.alert_file}", file=sys.stderr)
        return 1

    alert = load_alert(args.alert_file)
    result = investigate_alert(alert)
    payload = result.model_dump()

    if args.compact:
        print(json.dumps(payload, separators=(",", ":")))
    else:
        print(json.dumps(payload, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
