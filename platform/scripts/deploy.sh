#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PLATFORM_DIR}"

echo "==> AI Security Platform — deploy"
echo "    Working directory: ${PLATFORM_DIR}"
echo

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed or not on PATH." >&2
  exit 1
fi
echo "OK  Docker: $(docker --version)"

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: Docker Compose is not available (try: docker compose version)." >&2
  exit 1
fi
echo "OK  Docker Compose: $(docker compose version --short 2>/dev/null || docker compose version)"
echo

echo "==> Validating compose configuration"
docker compose config
echo

echo "==> Starting core platform (nginx, open-webui, observability)"
echo "    AI inference (ollama, ai-gateway) is optional — use the ai profile:"
echo "      docker compose --profile ai up -d"
echo "    Or: ./scripts/start-ai.sh"
echo
docker compose up -d
echo

echo "==> Service status"
docker compose ps
