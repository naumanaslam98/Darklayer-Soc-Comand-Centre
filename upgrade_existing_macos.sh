#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL_ROOT="${DARKLAYER_SOC_HOME:-$HOME/Library/Application Support/DarkLayerSOC}"

printf 'Upgrading DarkLayer SOC to v1.2 Live Monitoring...\n'
printf 'Existing runtime: %s\n' "$INSTALL_ROOT"
printf 'Existing .env and data/ will be preserved.\n\n'

chmod +x "$HERE/install_24x7_macos.sh"
exec "$HERE/install_24x7_macos.sh"
