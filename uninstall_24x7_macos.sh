#!/usr/bin/env bash
set -euo pipefail
UIDNUM="$(id -u)"
launchctl bootout "gui/$UIDNUM/com.darklayer.soc.server" 2>/dev/null || true
launchctl bootout "gui/$UIDNUM/com.darklayer.soc.macos-collector" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/com.darklayer.soc.server.plist" "$HOME/Library/LaunchAgents/com.darklayer.soc.macos-collector.plist"
echo "DarkLayer SOC launch agents removed. Data and .env were kept."
