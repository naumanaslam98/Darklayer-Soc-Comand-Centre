#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(cd "$(dirname "$0")" && pwd)"
INSTALL_ROOT="${DARKLAYER_SOC_HOME:-$HOME/Library/Application Support/DarkLayerSOC}"
LOG_ROOT="$HOME/Library/Logs/DarkLayerSOC"
LAUNCH_ROOT="$HOME/Library/LaunchAgents"

mkdir -p "$INSTALL_ROOT" "$LOG_ROOT" "$LAUNCH_ROOT"

# macOS privacy protections can prevent background LaunchAgents from reading
# Downloads/Desktop/Documents. Deploy the runtime to Application Support.
if [ "$SOURCE_ROOT" != "$INSTALL_ROOT" ]; then
  /usr/bin/rsync -a \
    --exclude '.venv/' \
    --exclude '.env' \
    --exclude 'data/' \
    "$SOURCE_ROOT/" "$INSTALL_ROOT/"

  # Preserve an already-generated environment from the extracted source on first install.
  if [ -f "$SOURCE_ROOT/.env" ] && [ ! -f "$INSTALL_ROOT/.env" ]; then
    cp "$SOURCE_ROOT/.env" "$INSTALL_ROOT/.env"
  fi
fi

ROOT="$INSTALL_ROOT"
cd "$ROOT"
mkdir -p data

# A Python venv contains absolute paths, so always rebuild it after deploying/moving.
rm -rf .venv
python3 -m venv .venv
.venv/bin/python -m pip install -q -U pip
.venv/bin/python -m pip install -q -r requirements.txt

if [ ! -f .env ]; then
  python3 scripts/generate_env.py
else
  chmod 600 .env
  echo "Preserved existing runtime .env."
fi

SERVER_PLIST="$LAUNCH_ROOT/com.darklayer.soc.server.plist"
COLLECTOR_PLIST="$LAUNCH_ROOT/com.darklayer.soc.macos-collector.plist"

cat > "$SERVER_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.darklayer.soc.server</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$ROOT/scripts/start_soc_24x7.sh</string></array>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$LOG_ROOT/soc-server.log</string>
  <key>StandardErrorPath</key><string>$LOG_ROOT/soc-server.err.log</string>
</dict></plist>
PLIST

cat > "$COLLECTOR_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.darklayer.soc.macos-collector</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$ROOT/scripts/start_macos_collector_24x7.sh</string></array>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$LOG_ROOT/macos-collector.log</string>
  <key>StandardErrorPath</key><string>$LOG_ROOT/macos-collector.err.log</string>
</dict></plist>
PLIST

chmod +x scripts/start_soc_24x7.sh scripts/start_macos_collector_24x7.sh scripts/macos_log_forwarder.py
chmod 600 "$SERVER_PLIST" "$COLLECTOR_PLIST"

UIDNUM="$(id -u)"
launchctl bootout "gui/$UIDNUM/com.darklayer.soc.server" 2>/dev/null || true
launchctl bootout "gui/$UIDNUM/com.darklayer.soc.macos-collector" 2>/dev/null || true

# Stop a stale server started from the old Downloads path, if present.
pkill -f "$HOME/Downloads/darklayer_soc_center_v1_1_24x7/.venv/bin/uvicorn" 2>/dev/null || true
sleep 1

launchctl bootstrap "gui/$UIDNUM" "$SERVER_PLIST"
launchctl bootstrap "gui/$UIDNUM" "$COLLECTOR_PLIST"
launchctl enable "gui/$UIDNUM/com.darklayer.soc.server"
launchctl enable "gui/$UIDNUM/com.darklayer.soc.macos-collector"
launchctl kickstart -k "gui/$UIDNUM/com.darklayer.soc.server"
sleep 2
launchctl kickstart -k "gui/$UIDNUM/com.darklayer.soc.macos-collector"
sleep 2

echo
echo "DarkLayer SOC v1.2 Live Monitoring installed in:"
echo "  $ROOT"
echo "Dashboard: http://127.0.0.1:8000"
echo "Runtime config: $ROOT/.env"
echo "Logs: $LOG_ROOT"
echo
echo "Check status from the extracted folder with:"
echo "  ./status_24x7_macos.sh"
