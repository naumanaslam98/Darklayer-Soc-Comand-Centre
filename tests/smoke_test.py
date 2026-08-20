import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

Path("data").mkdir(exist_ok=True)
Path("data/test_smoke.db").unlink(missing_ok=True)
os.environ.update({
    "SOC_ADMIN_USER": "ci-admin",
    "SOC_ADMIN_PASSWORD": "ci-only-password",
    "SOC_SECRET": "ci-secret-0123456789abcdef0123456789abcdef",
    "SOC_AGENT_API_KEY": "ci-agent-key-0123456789abcdef0123456789abcdef",
    "DATABASE_URL": "sqlite:///./data/test_smoke.db",
    "ENABLE_SYSLOG": "false",
})

from fastapi.testclient import TestClient
from app.main import app

with TestClient(app) as c:
    r = c.get("/api/health")
    assert r.status_code == 200 and r.json()["ok"]

    r = c.post("/api/login", json={"username": "ci-admin", "password": "ci-only-password"})
    assert r.status_code == 200
    token = r.json()["token"]
    h = {"Authorization": f"Bearer {token}"}

    r = c.post("/api/events", headers=h, json={
        "source": "EDR",
        "event_type": "process_creation",
        "asset": "TEST-ASSET-01",
        "user": "test-user",
        "src_ip": "10.0.0.5",
        "message": "powershell.exe -enc AAAA",
    })
    assert r.status_code == 200 and len(r.json()["alerts"]) >= 1

    r = c.post("/api/demo/generate", headers=h)
    assert r.status_code == 200
    assert r.json()["alerts"] >= 4

    for path in [
        "/api/dashboard", "/api/alerts", "/api/incidents", "/api/hunt?q=powershell",
        "/api/iocs", "/api/cases", "/api/analysts", "/api/sources", "/api/assets",
        "/api/identities", "/api/network/summary", "/api/detections",
    ]:
        r = c.get(path, headers=h)
        assert r.status_code == 200, (path, r.text)

    dash = c.get("/api/dashboard", headers=h).json()
    assert dash["metrics"]["active_alerts"] >= 1
    assert dash["metrics"]["events_24h"] >= 1
    assert len(c.get("/api/incidents", headers=h).json()) >= 1
    assert len(c.get("/api/assets", headers=h).json()) >= 1
    assert len(c.get("/api/detections", headers=h).json()) >= 7

print("SMOKE TEST: PASS")
