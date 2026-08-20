#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
UIDNUM="$(id -u)"
launchctl bootout "gui/$UIDNUM/com.darklayer.soc.server" 2>/dev/null || true
launchctl bootout "gui/$UIDNUM/com.darklayer.soc.macos-collector" 2>/dev/null || true
pkill -f "$HERE/.venv/bin/uvicorn" 2>/dev/null || true
chmod +x "$HERE/install_24x7_macos.sh" "$HERE/status_24x7_macos.sh"
exec "$HERE/install_24x7_macos.sh"
