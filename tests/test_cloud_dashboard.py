"""Tests for the dashboard routes (login, RBAC, event view, reports)."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_shield.cloud.auth import SessionManager, hash_password
from mcp_shield.cloud.dashboard import router as dashboard_router
from mcp_shield.cloud.db import Database


@pytest.fixture
def app_and_client(tmp_path):
    db = Database(tmp_path / "test.db")
    org = db.create_org("Acme")
    admin = db.create_user(org.id, "admin@acme.com", hash_password("pass123"), "admin")
    viewer = db.create_user(org.id, "viewer@acme.com", hash_password("pass123"), "viewer")
    analyst = db.create_user(org.id, "analyst@acme.com", hash_password("pass123"), "analyst")
    key = db.create_api_key(org.id, "prod")
    # Insert some events.
    db.insert_event(org.id, {"seq": 1, "ts": "2026-01-01T00:00:00Z", "decision": "deny",
                             "server": "fs", "tool": "exec", "args": {}, "reason": "blocked", "rule": "exec-rule"})
    db.insert_event(org.id, {"seq": 2, "ts": "2026-01-02T00:00:00Z", "decision": "allow",
                             "server": "fs", "tool": "read_file", "args": {}, "reason": "ok", "rule": "default"})

    app = FastAPI()
    app.include_router(dashboard_router)
    app.state.db = db
    app.state.session_manager = SessionManager(secret_key="test-secret")
    client = TestClient(app)
    yield client, db, org, admin, viewer, analyst
    db.close()


def _login(client, email, password="pass123"):
    resp = client.post("/login", data={"email": email, "password": password}, follow_redirects=False)
    return resp


def test_login_success(app_and_client):
    c, *_ = app_and_client
    resp = _login(c, "admin@acme.com")
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"
    # Session cookie set.
    assert "mcp_shield_session" in resp.headers.get("set-cookie", "")


def test_login_wrong_password(app_and_client):
    c, *_ = app_and_client
    resp = c.post("/login", data={"email": "admin@acme.com", "password": "wrong"}, follow_redirects=False)
    assert resp.status_code == 401


def test_login_unknown_email(app_and_client):
    c, *_ = app_and_client
    resp = c.post("/login", data={"email": "nobody@nowhere.com", "password": "x"}, follow_redirects=False)
    assert resp.status_code == 401


def test_dashboard_requires_login(app_and_client):
    c, *_ = app_and_client
    resp = c.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 403


def test_dashboard_shows_events(app_and_client):
    c, *_ = app_and_client
    _login(c, "admin@acme.com")
    resp = c.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 200
    assert "exec" in resp.text
    assert "read_file" in resp.text


def test_dashboard_filter_decision(app_and_client):
    c, *_ = app_and_client
    _login(c, "admin@acme.com")
    resp = c.get("/dashboard?decision=deny", follow_redirects=False)
    assert resp.status_code == 200
    assert "exec" in resp.text
    assert "read_file" not in resp.text


def test_event_detail(app_and_client):
    c, db, org, *_ = app_and_client
    _login(c, "admin@acme.com")
    events = db.query_events(org.id)
    # Find the deny event (exec tool).
    exec_event = [e for e in events if e.tool == "exec"][0]
    resp = c.get(f"/events/{exec_event.id}", follow_redirects=False)
    assert resp.status_code == 200
    assert "exec" in resp.text


def test_viewer_blocked_from_users(app_and_client):
    c, *_ = app_and_client
    _login(c, "viewer@acme.com")
    resp = c.get("/users", follow_redirects=False)
    assert resp.status_code == 403


def test_analyst_blocked_from_users(app_and_client):
    c, *_ = app_and_client
    _login(c, "analyst@acme.com")
    resp = c.get("/users", follow_redirects=False)
    assert resp.status_code == 403


def test_analyst_can_view_reports(app_and_client):
    c, *_ = app_and_client
    _login(c, "analyst@acme.com")
    resp = c.get("/reports", follow_redirects=False)
    assert resp.status_code == 200


def test_viewer_blocked_from_reports(app_and_client):
    c, *_ = app_and_client
    _login(c, "viewer@acme.com")
    resp = c.get("/reports", follow_redirects=False)
    assert resp.status_code == 403


def test_admin_can_create_user(app_and_client):
    c, *_ = app_and_client
    _login(c, "admin@acme.com")
    resp = c.post("/users", data={"email": "new@acme.com", "password": "pass", "role": "viewer"}, follow_redirects=False)
    assert resp.status_code == 302


def test_admin_can_create_key(app_and_client):
    c, *_ = app_and_client
    _login(c, "admin@acme.com")
    resp = c.post("/keys", data={"label": "staging"}, follow_redirects=False)
    assert resp.status_code == 302


def test_report_view(app_and_client):
    c, *_ = app_and_client
    _login(c, "admin@acme.com")
    resp = c.get("/reports/soc2", follow_redirects=False)
    assert resp.status_code == 200
    assert "SOC2" in resp.text


def test_report_csv_download(app_and_client):
    c, *_ = app_and_client
    _login(c, "admin@acme.com")
    resp = c.get("/reports/soc2/download", follow_redirects=False)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")


def test_logout(app_and_client):
    c, *_ = app_and_client
    _login(c, "admin@acme.com")
    resp = c.get("/logout", follow_redirects=False)
    assert resp.status_code == 302
    # After logout, dashboard is blocked.
    resp2 = c.get("/dashboard", follow_redirects=False)
    assert resp2.status_code == 403


def test_cross_org_isolation(app_and_client, tmp_path):
    """User in org A cannot see org B events."""
    c, db, org_a, *_ = app_and_client
    org_b = db.create_org("B")
    db.create_user(org_b.id, "b@b.com", hash_password("pass"), "admin")
    db.insert_event(org_b.id, {"seq": 1, "ts": "t", "decision": "deny", "server": "s", "tool": "secret_tool", "args": {}, "reason": "x", "rule": "r"})
    # Login as org A admin.
    _login(c, "admin@acme.com")
    resp = c.get("/dashboard", follow_redirects=False)
    assert "secret_tool" not in resp.text  # org B's events not visible


# ----------------------------------------------------------- registration


def test_register_page_loads(app_and_client):
    c, *_ = app_and_client
    resp = c.get("/register", follow_redirects=False)
    assert resp.status_code == 200
    assert "Create" in resp.text or "register" in resp.text.lower()


def test_register_creates_new_org(app_and_client):
    """Self-service registration creates a new org + admin user."""
    c, db, *_ = app_and_client
    resp = c.post("/register", data={
        "org_name": "NewCorp",
        "email": "admin@newcorp.com",
        "password": "securepass123",
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"
    # Session cookie set.
    assert "mcp_shield_session" in resp.headers.get("set-cookie", "")
    # Org created.
    user = db.get_user_by_email("admin@newcorp.com")
    assert user is not None
    assert user.role == "admin"
    # The new org is different from the existing one.
    assert user.org_id != app_and_client[2].id


def test_register_short_password_rejected(app_and_client):
    c, db, *_ = app_and_client
    resp = c.post("/register", data={
        "org_name": "NewCorp",
        "email": "admin@newcorp.com",
        "password": "short",
    }, follow_redirects=False)
    assert resp.status_code == 400
    assert "at least 8" in resp.text
    # User NOT created.
    assert db.get_user_by_email("admin@newcorp.com") is None


def test_register_duplicate_email_rejected(app_and_client):
    c, db, org, admin, *_ = app_and_client
    resp = c.post("/register", data={
        "org_name": "AnotherCorp",
        "email": admin.email,  # already exists
        "password": "securepass123",
    }, follow_redirects=False)
    assert resp.status_code == 400
    assert "already registered" in resp.text


def test_register_empty_org_name_rejected(app_and_client):
    c, db, *_ = app_and_client
    resp = c.post("/register", data={
        "org_name": "   ",
        "email": "admin@test.com",
        "password": "securepass123",
    }, follow_redirects=False)
    assert resp.status_code == 400
    assert "required" in resp.text


def test_register_auto_login(app_and_client):
    """After registration, the user is auto-logged-in (session cookie set)."""
    c, *_ = app_and_client
    resp = c.post("/register", data={
        "org_name": "AutoLoginCorp",
        "email": "admin@autologin.com",
        "password": "securepass123",
    }, follow_redirects=False)
    # Follow the redirect with the session cookie.
    resp2 = c.get("/dashboard", follow_redirects=False)
    assert resp2.status_code == 200  # logged in, can see dashboard


def test_register_creates_default_api_key(app_and_client):
    c, db, *_ = app_and_client
    c.post("/register", data={
        "org_name": "KeyCorp",
        "email": "admin@keycorp.com",
        "password": "securepass123",
    }, follow_redirects=False)
    user = db.get_user_by_email("admin@keycorp.com")
    keys = db.list_api_keys(user.org_id)
    assert len(keys) == 1
    assert keys[0].label == "default"
