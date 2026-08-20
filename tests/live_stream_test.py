import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

Path("data").mkdir(exist_ok=True)
Path("data/test_live.db").unlink(missing_ok=True)
os.environ.update({
    "SOC_ADMIN_USER": "ci-admin",
    "SOC_ADMIN_PASSWORD": "ci-only-password",
    "SOC_SECRET": "ci-secret-0123456789abcdef0123456789abcdef",
    "SOC_AGENT_API_KEY": "ci-agent-key-0123456789abcdef0123456789abcdef",
    "DATABASE_URL": "sqlite:///./data/test_live.db",
    "ENABLE_SYSLOG": "false",
})

from fastapi.testclient import TestClient
from app.main import app

with TestClient(app) as c:
    login = c.post("/api/login", json={"username": "ci-admin", "password": "ci-only-password"})
    assert login.status_code == 200, login.text
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    recent_before = c.get("/api/events/recent?limit=5", headers=headers)
    assert recent_before.status_code == 200

    with c.websocket_connect(f"/ws/events?token={token}") as ws:
        payload = {
            "source": "TEST_SENSOR",
            "event_type": "auth_failure",
            "severity": "medium",
            "asset": "TEST-MAC-01",
            "user": "test-user",
            "src_ip": "127.0.0.1",
            "message": "authentication failed live stream smoke test",
        }
        r = c.post("/api/events", headers=headers, json=payload)
        assert r.status_code == 200, r.text
        live = ws.receive_json()
        assert live["source"] == "TEST_SENSOR"
        assert live["event_type"] == "auth_failure"
        assert live["asset"] == "TEST-MAC-01"
        event_id = live["id"]

    detail = c.get(f"/api/events/{event_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["event"]["message"] == payload["message"]

    stats = c.get("/api/live/stats", headers=headers)
    assert stats.status_code == 200, stats.text
    assert stats.json()["events_24h"] >= 1

print("LIVE STREAM TEST: PASS")
