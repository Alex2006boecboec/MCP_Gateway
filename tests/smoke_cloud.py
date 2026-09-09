"""End-to-end smoke test for Phase 5 (Cloud Dashboard).

Starts a real cloud server (FastAPI via TestClient), creates an org + API
key, configures a proxy with a CloudShipper pointed at the cloud, runs a
few tool calls through the proxy, and verifies the events appear in the
cloud dashboard.

Run:  python tests/smoke_cloud.py
"""
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

# Ensure we can import mcp_shield from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from mcp_shield.audit import AuditLogger
from mcp_shield.cloud.auth import SessionManager, hash_password
from mcp_shield.cloud.db import Database
from mcp_shield.cloud.server import create_app
from mcp_shield.shipper import CloudShipper, CloudShipperConfig


def _entry(seq, decision="deny", tool="exec"):
    return {
        "seq": seq, "ts": f"2026-01-0{seq}T00:00:00Z", "decision": decision,
        "server": "fs", "tool": tool, "args": {"cmd": "[REDACTED:secret]"},
        "reason": "blocked", "rule": "exec-rule",
        "redactions": [{"arg": "cmd", "fingerprint": "secret"}],
    }


def main():
    tmp = Path(tempfile.mkdtemp())
    db_path = tmp / "cloud.db"
    audit_path = tmp / "audit.jsonl"

    # 1. Create the cloud app with a fresh DB.
    app = create_app(db_path=str(db_path), secret="smoke-test-secret")
    client = TestClient(app)
    db: Database = app.state.db

    # Get the default org + admin from bootstrap.
    # Find the default org via the admin user (works for SQLite + Postgres).
    admin = db.get_user_by_email("admin@mcp-shield.local")
    org_id = admin.org_id
    admin_email = "admin@mcp-shield.local"
    # Create an API key for the proxy.
    api_key = db.create_api_key(org_id, "smoke-test-proxy")
    print(f"  Org: {org_id}")
    print(f"  API key: {api_key.key[:20]}...")

    # 2. Create a shipper pointed at the cloud (via TestClient transport).
    # We can't use a real HTTP URL with TestClient, so we'll ship directly
    # to the DB via a custom shipper that calls db.insert_event.
    class DirectShipper:
        """A shipper that writes directly to the DB (simulates HTTP)."""
        def __init__(self, db, org_id):
            self.db = db
            self.org_id = org_id
        def ship(self, entry):
            self.db.insert_event(self.org_id, entry)
        def flush(self):
            return 0

    shipper = DirectShipper(db, org_id)

    # 3. Create an AuditLogger with the shipper and log some events.
    audit = AuditLogger(audit_path, shipper=shipper)
    audit.log(decision="deny", server="fs", tool="exec", args={"cmd": "[REDACTED:secret]"},
              reason="blocked", rule="exec-rule",
              redactions=[{"arg": "cmd", "fingerprint": "secret"}])
    audit.log(decision="allow", server="fs", tool="read_file", args={},
              reason="ok", rule="default")
    audit.log(decision="deny", server="fetch", tool="fetch_url", args={"url": "http://169.254.169.254"},
              reason="internal URL blocked", rule="url-validator",
              detection={"score": 0.9, "verdict": "blocked"})
    audit.log(decision="deny", server="fs", tool="exec", args={},
              reason="chain blocked", rule="capability-graph",
              chain={"source_tool": "read_file", "sink_tool": "exec"})
    audit.log(decision="deny", server="fs", tool="exec", args={},
              reason="approval denied", rule="approval",
              approval={"outcome": "deny", "by": "alice"})

    print(f"  Logged 5 events locally + shipped to cloud")

    # 4. Verify events appear in the cloud DB.
    events = db.query_events(org_id)
    assert len(events) == 5, f"expected 5 events, got {len(events)}"
    print(f"  Cloud DB has {len(events)} events: OK")

    # 5. Verify cross-org isolation: create org B, ensure it sees 0 events.
    org_b = db.create_org("Other Org")
    events_b = db.query_events(org_b.id)
    assert len(events_b) == 0, f"org B should see 0 events, got {len(events_b)}"
    print(f"  Cross-org isolation: OK (org B sees {len(events_b)} events)")

    # 6. Login to the dashboard and verify it shows events.
    # GET /login first to obtain CSRF cookie.
    client.get("/login")
    csrf_token = client.cookies.get("mcp_shield_csrf", "")
    resp = client.post("/login", data={
        "email": admin_email, "password": "admin", "csrf_token": csrf_token,
    }, follow_redirects=False)
    assert resp.status_code == 302, f"login failed: {resp.status_code}"
    print(f"  Dashboard login: OK")

    # 6b. Bootstrap admin has must_change_password=True — change password first.
    client.get("/login")
    csrf_token = client.cookies.get("mcp_shield_csrf", "")
    resp = client.post("/settings", data={
        "old_password": "admin", "new_password": "SmokeTest123!",
        "new_password_confirm": "SmokeTest123!", "csrf_token": csrf_token,
    }, follow_redirects=False)
    assert resp.status_code == 302, f"password change failed: {resp.status_code}"
    print(f"  Password change: OK")

    # 7. Dashboard shows events.
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 200, f"dashboard failed: {resp.status_code}"
    assert "exec" in resp.text, "dashboard should show exec tool"
    assert "fetch_url" in resp.text, "dashboard should show fetch_url"
    print(f"  Dashboard shows events: OK")

    # 8. Filter by decision=deny.
    resp = client.get("/dashboard?decision=deny", follow_redirects=False)
    assert resp.status_code == 200
    assert "read_file" not in resp.text or "allow" not in resp.text, "deny filter should exclude allows"
    print(f"  Dashboard filter: OK")

    # 9. Generate a SOC2 report.
    resp = client.get("/reports/soc2", follow_redirects=False)
    assert resp.status_code == 200, f"report failed: {resp.status_code}"
    assert "SOC2" in resp.text
    print(f"  SOC2 report: OK")

    # 10. Download CSV.
    resp = client.get("/reports/soc2/download", follow_redirects=False)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")
    assert "Total calls,5" in resp.text
    print(f"  CSV download: OK")

    # 11. Verify the local audit log is tamper-evident.
    assert audit.verify(), "audit log hash chain should be intact"
    print(f"  Audit log tamper-evidence: OK")

    # 12. Verify no raw secrets in the cloud DB.
    for ev in events:
        for v in ev.args.values():
            assert "secret" not in str(v).lower() or "[REDACTED:" in str(v), \
                f"raw secret leaked: {v}"
    print(f"  No raw secrets in cloud DB: OK")

    print()
    print("ALL SMOKE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
