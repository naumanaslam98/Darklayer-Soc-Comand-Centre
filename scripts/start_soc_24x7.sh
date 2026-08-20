#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
set -a
[ -f .env ] && source .env
set +a
exec "$ROOT/.venv/bin/uvicorn" app.main:app --host "${SOC_BIND_HOST:-127.0.0.1}" --port "${SOC_PORT:-8000}"
