#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PLATFORM_DIR}"

echo "==> AI Security Platform — stop"
echo "    Working directory: ${PLATFORM_DIR}"
echo

echo "==> Stopping services (volumes are preserved)"
docker compose down

echo
echo "Done. Persistent volumes were not removed."
