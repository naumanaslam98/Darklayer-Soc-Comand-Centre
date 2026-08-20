# DarkLayer SOC Center

**Version 1.2.0 — 24/7 Live Monitoring**

DarkLayer SOC Center is a local Security Operations Center platform for macOS and lab environments. It continuously ingests security-relevant telemetry, stores events, runs detections, correlates alerts into incidents, streams live events to the browser, supports threat hunting and IOC intelligence, and can send severe-alert email notifications.

> **Status:** working development SOC platform. It is not yet a production-scale SIEM/EDR/XDR replacement and should not be exposed directly to the public internet.

## Core capabilities

- 24/7 macOS Unified Log collector using a machine API key.
- Real-time **Live Events** terminal via `WS /ws/events`.
- Real-time alert delivery via `WS /ws/alerts`.
- Event persistence and historical investigation.
- Detection rules for suspicious PowerShell, brute-force authentication, privilege changes, port scans, malware indicators, large outbound transfers, and IOC matches.
- MITRE ATT&CK tactic/technique mapping.
- Automatic alert-to-incident correlation and risk scoring.
- Alert queue, analyst assignment, incident investigation, threat hunting, IOC intelligence, assets, identities, network analytics, detection health, cases, and team workload.
- UDP syslog ingestion and Suricata `eve.json` forwarding.
- Optional SMTP notifications for High/Critical alerts.
- macOS `launchd` RunAtLoad + KeepAlive deployment.
- Docker support for the SOC backend.

## Architecture

```text
macOS / Syslog / API / Suricata
              |
              v
          Collectors
              |
              v
       Event Ingestion API
              |
      +-------+--------+
      |                |
      v                v
  Event Store       Live Event WS
      |
      v
 Detection Engine
      |
      v
    Alerts -----------> Live Alert WS
      |
      v
 Correlation Engine
      |
      v
   Incidents
      |
      +--> Dashboard / Investigation
      +--> Email notification (optional)
```

More detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Repository structure

```text
DarkLayerSOC/
├── app/                    # FastAPI backend, detections, correlation, UI
│   └── static/             # SOC web dashboard
├── scripts/                # Collectors, startup helpers, test utilities
├── tests/                  # Smoke and WebSocket live-stream tests
├── docs/                   # Architecture and deployment documentation
├── .github/workflows/      # GitHub Actions CI
├── .env.example            # Safe configuration template
├── .gitignore              # Excludes secrets, databases and runtime files
├── docker-compose.yml
├── Dockerfile
├── install_24x7_macos.sh
├── run_local.sh
├── SECURITY.md
├── CONTRIBUTING.md
└── CHANGELOG.md
```

## Quick start — local development

Requirements: macOS/Linux, Python 3.11+ (3.12 recommended).

```bash
git clone <YOUR_REPOSITORY_URL>
cd DarkLayerSOC
python3 scripts/generate_env.py
./run_local.sh
```

The environment generator creates a Git-ignored `.env`, random administrator password, signing secret, and collector API key. Store the generated administrator password securely.

Open:

```text
http://127.0.0.1:8000
```

## 24/7 macOS installation

```bash
chmod +x install_24x7_macos.sh
./install_24x7_macos.sh
```

The runtime is installed in:

```text
~/Library/Application Support/DarkLayerSOC
```

Check status:

```bash
cd "$HOME/Library/Application Support/DarkLayerSOC"
./status_24x7_macos.sh
```

Expected core state:

```text
SOC server:      state = running
macOS collector: state = running
API health:      ok = true
```

## Test live macOS telemetry

```bash
./test_live_macos_event.sh
```

The helper uses macOS `logger` to create an authentication-failure-style Unified Log event. It should be collected and appear in **Live Events** after a few seconds.

You can confirm persistence with Threat Hunting or the events API.

## Email notifications

Edit the generated `.env` and configure the optional SMTP section:

```env
EMAIL_ALERT_MIN_SEVERITY=high
ALERT_EMAIL_TO=analyst@example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-smtp-user
SMTP_PASSWORD=your-app-password
SMTP_FROM=soc-alerts@example.com
SMTP_USE_TLS=true
SMTP_USE_SSL=false
```

Then restart the SOC server and test:

```bash
set -a
source .env
set +a
PYTHONPATH="$PWD" .venv/bin/python scripts/test_email.py
```

Never commit the real `.env` file or SMTP password.

## Docker

```bash
python3 scripts/generate_env.py
docker compose up --build -d
```

The compose file binds both the dashboard and UDP syslog listener to localhost by default.

## Tests

```bash
python -m compileall -q app scripts tests
python tests/smoke_test.py
python tests/live_stream_test.py
```

The same checks run in GitHub Actions.

## Security defaults

- No real `.env` is included in this repository.
- `.env`, SQLite databases, logs, virtual environments, backups, and local runtime artifacts are Git-ignored.
- Required administrator password, signing secret, and machine API key must be provided at runtime.
- The environment generator creates cryptographically random local values.
- Dashboard and syslog defaults are localhost-only.
- Collected telemetry should be treated as sensitive operational data.

Read [`SECURITY.md`](SECURITY.md) before exposing or extending the system.

## Current scope boundary

The macOS sensor currently consumes a filtered subset of Unified Logs. It does **not** yet provide complete EDR-level visibility such as every process creation, every network/DNS event, full file-integrity monitoring, EndpointSecurity framework telemetry, durable enterprise message queues, multi-tenant isolation, or production-scale search/storage.

Potential future layers include osquery/EndpointSecurity telemetry, Sigma-style detection content, OpenSearch, PostgreSQL, Redis/queues, TLS-authenticated collectors, RBAC/MFA/SSO, SOAR playbooks, and richer threat-intelligence enrichment.

## Push to GitHub

This folder is already structured as a GitHub repository. Create an empty GitHub repository, then run:

```bash
git init
git branch -M main
git add .
git status
git commit -m "Initial commit: DarkLayer SOC Center v1.2"
git remote add origin https://github.com/YOUR_USERNAME/DarkLayerSOC.git
git push -u origin main
```

Review `git status` before the first commit. A real `.env`, databases, logs, and virtual environments must not appear. See [`docs/GITHUB_PUSH.md`](docs/GITHUB_PUSH.md).

## License

Copyright © 2026 DarkLayer Tech. All rights reserved. See [`LICENSE`](LICENSE).
