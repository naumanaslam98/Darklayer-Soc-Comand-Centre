#!/usr/bin/env python3
"""Always-on macOS Unified Log collector for DarkLayer SOC v1.2.

The collector forwards security-relevant macOS Unified Log events to the
machine-authenticated ingestion endpoint. It uses a persistent agent API key,
not an analyst login token, and tolerates NDJSON framing quirks.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

BASE = os.getenv("SOC_URL", "http://127.0.0.1:8000").rstrip("/")
URL = BASE + "/api/agent/events"
AGENT_KEY = os.getenv("SOC_AGENT_API_KEY", "")
HOST = socket.gethostname()
PREDICATE = os.getenv(
    "SOC_MACOS_LOG_PREDICATE",
    '(eventMessage CONTAINS[c] "fail") OR (eventMessage CONTAINS[c] "denied") OR '
    '(eventMessage CONTAINS[c] "malware") OR (eventMessage CONTAINS[c] "sudo") OR '
    '(eventMessage CONTAINS[c] "authentication") OR (eventMessage CONTAINS[c] "ssh") OR '
    '(eventMessage CONTAINS[c] "quarantine") OR (eventMessage CONTAINS[c] "XProtect") OR '
    '(subsystem CONTAINS[c] "security")'
)

if not AGENT_KEY:
    print("SOC_AGENT_API_KEY is required", file=sys.stderr)
    raise SystemExit(2)


def classify(msg: str) -> tuple[str, str]:
    m = msg.lower()
    if ("failed" in m or "fail" in m) and any(x in m for x in ("login", "auth", "password", "ssh")):
        return "auth_failure", "medium"
    if "sudo" in m or "privilege" in m or "administrator group" in m:
        return "privilege_change", "medium"
    if any(x in m for x in ("malware", "xprotect", "quarantine", "trojan", "ransomware")):
        return "security_event", "high"
    if "denied" in m or "not permitted" in m:
        return "access_denied", "low"
    return "macos_event", "info"


def send(raw: dict):
    msg = raw.get("eventMessage") or raw.get("message") or raw.get("composedMessage") or ""
    process = raw.get("process") or raw.get("processImagePath") or raw.get("senderImagePath") or ""
    event_type, severity = classify(msg)
    body = {
        "source": "macos_unified_log",
        "event_type": event_type,
        "severity": severity,
        "asset": HOST,
        "user": raw.get("user") or raw.get("userName") or None,
        "message": f"{process}: {msg}" if process else msg,
        "raw": raw,
    }
    req = urllib.request.Request(
        URL,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-Agent-Key": AGENT_KEY},
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        r.read()


def parse_records(line: str):
    """Parse NDJSON plus adjacent/fragmented JSON without killing the stream."""
    text = line.strip()
    if not text:
        return []
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            return [value]
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        return []
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    records = []
    pos = 0
    while pos < len(text):
        while pos < len(text) and (text[pos].isspace() or text[pos] in ",[]"):
            pos += 1
        if pos >= len(text):
            break
        if text[pos] not in "{[":
            candidates = [x for x in (text.find("{", pos), text.find("[", pos)) if x != -1]
            if not candidates:
                break
            pos = min(candidates)
        try:
            value, new_pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            pos += 1
            continue
        if isinstance(value, dict):
            records.append(value)
        elif isinstance(value, list):
            records.extend(x for x in value if isinstance(x, dict))
        pos = new_pos
    return records


def run_stream():
    cmd = [
        "/usr/bin/log", "stream", "--style", "ndjson", "--color", "none",
        "--type", "log", "--predicate", PREDICATE,
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    print(f"Forwarding filtered macOS security logs from {HOST} -> {URL}", flush=True)
    assert proc.stdout is not None
    ignored = 0
    last_notice = time.monotonic()
    for line in proc.stdout:
        records = parse_records(line)
        if not records:
            ignored += 1
            now = time.monotonic()
            if ignored >= 50 and now - last_notice >= 60:
                print(f"collector parser notice: ignored {ignored} non-event/framing lines", file=sys.stderr, flush=True)
                ignored = 0
                last_notice = now
            continue
        for raw in records:
            if raw.get("finished") is not None:
                continue
            if not any(key in raw for key in ("eventMessage", "message", "composedMessage", "process", "processImagePath", "subsystem")):
                continue
            try:
                send(raw)
            except Exception as exc:
                print(f"collector send failure: {exc}", file=sys.stderr, flush=True)
                time.sleep(1)
    return proc.wait()


while True:
    try:
        rc = run_stream()
        print(f"macOS log stream exited rc={rc}; restarting in 3s", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print(f"collector failure: {exc}; restarting in 3s", file=sys.stderr, flush=True)
    time.sleep(3)
