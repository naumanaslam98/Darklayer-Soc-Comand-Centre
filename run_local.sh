#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
mkdir -p data

if [ ! -f .env ]; then
  python3 scripts/generate_env.py
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
python -m pip install -q -U pip
python -m pip install -q -r requirements.txt

set -a
source .env
set +a

exec uvicorn app.main:app --host 127.0.0.1 --port 8000
