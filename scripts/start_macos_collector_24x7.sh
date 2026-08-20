#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
set -a
[ -f .env ] && source .env
set +a

SOC_URL="${SOC_URL:-http://127.0.0.1:8000}"
echo "Waiting for DarkLayer SOC server at $SOC_URL ..."

for _ in {1..60}; do
  if /usr/bin/curl -fsS "$SOC_URL/api/health" >/dev/null 2>&1; then
    echo "SOC server is ready. Starting macOS collector."
    exec "$ROOT/.venv/bin/python" "$ROOT/scripts/macos_log_forwarder.py"
  fi
  sleep 1
done

echo "SOC server did not become ready within 60 seconds." >&2
exit 1
