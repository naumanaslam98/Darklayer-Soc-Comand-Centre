# Deployment

## macOS 24/7 local deployment

From a clone or extracted release:

```bash
chmod +x install_24x7_macos.sh
./install_24x7_macos.sh
```

The runtime is deployed to:

```text
~/Library/Application Support/DarkLayerSOC
```

LaunchAgents keep the SOC server and macOS collector running after login and restart them if they exit.

Check status:

```bash
cd "$HOME/Library/Application Support/DarkLayerSOC"
./status_24x7_macos.sh
```

Open the dashboard:

```bash
open http://127.0.0.1:8000
```

## Local development

```bash
python3 scripts/generate_env.py
./run_local.sh
```

## Docker

Generate `.env` first:

```bash
python3 scripts/generate_env.py
docker compose up --build -d
```

The Docker compose file maps the web UI and syslog listener to localhost only.

## Email alerts

Configure the optional SMTP variables in `.env`, restart the server, then test with:

```bash
set -a
source .env
set +a
PYTHONPATH="$PWD" .venv/bin/python scripts/test_email.py
```

Use an application-specific password when required by the mail provider. Never commit the generated `.env`.
