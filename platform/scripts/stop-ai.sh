#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PLATFORM_DIR}"

echo "==> AI Security Platform — stop AI profile"
echo "    Working directory: ${PLATFORM_DIR}"
echo "    Core platform (nginx, open-webui, observability) is left running."
echo

echo "==> Stopping ai-gateway and ollama"
docker compose --profile ai stop ai-gateway ollama

echo
echo "Done."
