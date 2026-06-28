#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PLATFORM_DIR}"

echo "==> AI Security Platform — status"
echo "    Working directory: ${PLATFORM_DIR}"
echo

echo "==> Service status"
docker compose ps
echo

echo "==> Recent logs (last 25 lines per service)"
docker compose logs --tail=25 nginx open-webui ollama
echo

echo "==> Nginx health check (http://localhost)"
if curl -fsS --max-time 5 -o /dev/null -w "HTTP %{http_code}\n" http://localhost; then
  echo "OK  Nginx is responding on http://localhost"
else
  echo "WARN Nginx is not responding on http://localhost (see logs above)" >&2
  exit 1
fi
