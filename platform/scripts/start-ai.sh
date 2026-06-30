#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PLATFORM_DIR}"

echo "==> AI Security Platform — start AI profile"
echo "    Working directory: ${PLATFORM_DIR}"
echo

echo "==> Starting ollama and ai-gateway"
docker compose --profile ai up -d ollama ai-gateway
echo

echo "==> Service status"
docker compose ps
