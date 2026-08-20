#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.mailer import email_enabled, send_alert_email

sample = {
    "severity": "critical",
    "title": "DarkLayer SOC email test",
    "rule_id": "TEST-EMAIL-001",
    "mitre_tactic": "Test",
    "mitre_technique": "T0000",
    "asset": "LOCAL-TEST-ASSET",
    "user": "local-user",
    "src_ip": "127.0.0.1",
    "dst_ip": None,
    "status": "new",
    "description": "If you received this, severe-alert SMTP notifications are configured correctly.",
}

print("email_enabled=", email_enabled())
print("sent=", send_alert_email(sample))
