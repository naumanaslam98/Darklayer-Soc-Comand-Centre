#!/usr/bin/env python3
"""Generate a secure local .env from .env.example.

The generated .env is runtime configuration and is intentionally excluded
from Git by .gitignore.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / ".env.example"
TARGET = ROOT / ".env"

if TARGET.exists():
    print(f"Existing {TARGET} preserved.")
    raise SystemExit(0)

text = EXAMPLE.read_text()
admin_password = secrets.token_urlsafe(18)
secret = secrets.token_hex(32)
agent_key = secrets.token_urlsafe(48)

text = text.replace("CHANGE_ME_GENERATE_A_STRONG_PASSWORD", admin_password)
text = text.replace("CHANGE_ME_GENERATE_A_LONG_RANDOM_SECRET", secret)
text = text.replace("CHANGE_ME_GENERATE_A_LONG_RANDOM_AGENT_KEY", agent_key)
TARGET.write_text(text)
os.chmod(TARGET, 0o600)

print(f"Created secure runtime configuration: {TARGET}")
print("Admin username: admin")
print(f"Generated admin password: {admin_password}")
print("Store the password in a password manager. The .env file is Git-ignored.")
