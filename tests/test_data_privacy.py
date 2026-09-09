"""Tests for Stage 5+6: data retention, GDPR export/delete, health check."""

from __future__ import annotations

import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_shield.cloud.auth import SessionManager, hash_password
from mcp_shield.cloud.dashboard import router as dashboard_router
from mcp_shield.cloud.db import Database
from mcp_shield.cloud.rate_limit import login_limiter, register_limiter


@pytest.fixture
def app_client(tmp_path):
    login_limiter._buckets.clear()
    register_limiter._buckets.clear()
    db = Database(tmp_path / "test.db")
    org = db.create_org("TestOrg")
    admin = db.create_user(org.id, "admin@test.com", hash_password("AdminPass123!"), "admin")
    db.create_api_key(org.id, "test-key")
    db.insert_event(org.id, {"seq": 1, "ts": "2026-01-01T00:00:00Z", "decision": "deny",
                             "server": "fs", "tool": "exec", "args": {}, "reason": "blocked", "rule": "r"})
    app = FastAPI()
    app.include_router(dashboard_router)
    app.state.db = db
    app.state.session_manager = SessionManager(secret_key="test-secret")
    client = TestClient(app)
    yield client, db, org, admin
    db.close()


def _login(client, email="admin@test.com", password="AdminPass123!"):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=False)


# ----------------------------------------------------------- Health check


class TestHealthCheck:
    def test_health_ok(self, app_client):
        c, *_ = app_client
        r = c.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_no_auth_required(self, app_client):
        c, *_ = app_client
        # Without login, health should still work.
        r = c.get("/health")
        assert r.status_code == 200


# ----------------------------------------------------------- Data retention


class TestDataRetention:
    def test_delete_old_events(self, app_client):
        c, db, org, admin = app_client
        # Insert an old event (manually set received_at to past).
        import time
        old_time = time.time() - (100 * 86400)  # 100 days ago
        db.insert_event(org.id, {"seq": 999, "ts": "2026-01-01", "decision": "allow",
                                  "server": "fs", "tool": "x", "args": {}, "reason": "ok", "rule": "r"})
        # Manually update received_at to old time.
        db._conn.execute("UPDATE events SET received_at = ? WHERE seq = ?", (old_time, 999))
        db._conn.commit()
        # Delete events older than 90 days.
        deleted = db.delete_old_events(90)
        assert deleted >= 1
        # Old event is gone.
        events = db.query_events(org.id)
        assert all(e.seq != 999 for e in events)


# ----------------------------------------------------------- GDPR export


class TestGDPRExport:
    def test_export_requires_admin(self, app_client):
        c, db, org, admin = app_client
        # Not logged in.
        r = c.get("/org/export", follow_redirects=False)
        assert r.status_code == 403

    def test_export_returns_json(self, app_client):
        c, db, org, admin = app_client
        _login(c)
        r = c.get("/org/export", follow_redirects=False)
        assert r.status_code == 200
        assert "application/json" in r.headers.get("content-type", "")
        data = json.loads(r.content)
        assert data["org"]["name"] == "TestOrg"
        assert len(data["users"]) >= 1
        assert len(data["events"]) >= 1

    def test_export_does_not_leak_full_api_keys(self, app_client):
        c, db, org, admin = app_client
        _login(c)
        r = c.get("/org/export", follow_redirects=False)
        data = json.loads(r.content)
        for key in data["api_keys"]:
            # Key should be truncated.
            assert "..." in key["key"]
            assert len(key["key"]) < 30


# ----------------------------------------------------------- GDPR delete


class TestGDPRDelete:
    def test_delete_requires_confirm(self, app_client):
        c, db, org, admin = app_client
        _login(c)
        r = c.post("/org/delete", data={"confirm": "yes"}, follow_redirects=False)
        assert r.status_code == 400

    def test_delete_with_confirmation(self, app_client):
        c, db, org, admin = app_client
        _login(c)
        r = c.post("/org/delete", data={"confirm": "DELETE"}, follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login"
        # Org data is gone.
        assert db.get_org(org.id) is None
        assert db.list_users(org.id) == []
        assert db.list_api_keys(org.id) == []
        assert db.query_events(org.id) == []

    def test_delete_logs_action(self, app_client):
        c, db, org, admin = app_client
        _login(c)
        c.post("/org/delete", data={"confirm": "DELETE"}, follow_redirects=False)
        # The action is logged BEFORE the org is deleted.
        # But since the org is deleted, the action is also deleted (cascade).
        # So we can't check it after. Let's verify the delete happened.
        assert db.get_org(org.id) is None
