#!/usr/bin/env bash
set -u
ROOT="${DARKLAYER_SOC_HOME:-$HOME/Library/Application Support/DarkLayerSOC}"
LOG_ROOT="$HOME/Library/Logs/DarkLayerSOC"
UIDNUM="$(id -u)"

echo "=== SOC server ==="
launchctl print "gui/$UIDNUM/com.darklayer.soc.server" 2>/dev/null | grep -E 'state =|pid =|last exit code' || echo "not loaded"
echo
echo "=== macOS collector ==="
launchctl print "gui/$UIDNUM/com.darklayer.soc.macos-collector" 2>/dev/null | grep -E 'state =|pid =|last exit code' || echo "not loaded"
echo
echo "=== API health ==="
curl -fsS http://127.0.0.1:8000/api/health || true
echo
echo "=== install path ==="
echo "$ROOT"
echo
echo "=== recent server errors ==="
tail -n 12 "$LOG_ROOT/soc-server.err.log" 2>/dev/null || true
echo
echo "=== recent collector errors ==="
tail -n 15 "$LOG_ROOT/macos-collector.err.log" 2>/dev/null || true
