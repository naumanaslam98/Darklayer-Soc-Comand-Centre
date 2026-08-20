#!/usr/bin/env bash
set -euo pipefail
MESSAGE="authentication failed login DarkLayer SOC live monitoring test"
/usr/bin/logger -p user.warning "$MESSAGE"
echo "Test security event sent to macOS Unified Logging."
echo "Message: $MESSAGE"
echo "Open Dashboard -> Live Events and wait a few seconds."
