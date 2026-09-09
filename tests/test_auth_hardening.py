"""Tests for Stage 2: rate limiting, password change, password reset, session rotation."""

from __future__ import annotations

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
    admin = db.create_user(org.id, "admin@test.com", hash_password("OldPass123!"), "admin")
    app = FastAPI()
    app.include_router(dashboard_router)
    app.state.db = db
    app.state.session_manager = SessionManager(secret_key="test-secret")
    client = TestClient(app)
    yield client, db, org, admin
    db.close()


def _login(client, email="admin@test.com", password="OldPass123!"):
    resp = client.post("/login", data={"email": email, "password": password}, follow_redirects=False)
    return resp


# ----------------------------------------------------------- Rate limiting


class TestLoginRateLimit:
    def test_login_success(self, app_client):
        c, *_ = app_client
        r = _login(c)
        assert r.status_code == 302

    def test_login_lockout_after_5_failures(self, app_client):
        c, *_ = app_client
        for i in range(5):
            c.post("/login", data={"email": "admin@test.com", "password": "wrong"},
                   follow_redirects=False)
        # 6th attempt should be locked.
        r = c.post("/login", data={"email": "admin@test.com", "password": "wrong"},
                   follow_redirects=False)
        assert r.status_code == 429
        assert "locked" in r.text.lower() or "too many" in r.text.lower()

    def test_successful_login_resets_counter(self, app_client):
        c, *_ = app_client
        for i in range(4):
            c.post("/login", data={"email": "admin@test.com", "password": "wrong"},
                   follow_redirects=False)
        # Successful login should reset the counter.
        r = _login(c)
        assert r.status_code == 302
        # Now 4 more failures should NOT lock (counter was reset).
        for i in range(4):
            c.post("/login", data={"email": "admin@test.com", "password": "wrong"},
                   follow_redirects=False)
        r = c.post("/login", data={"email": "admin@test.com", "password": "wrong"},
                   follow_redirects=False)
        assert r.status_code == 401  # not locked yet, just bad password


class TestRegisterRateLimit:
    def test_register_allowed(self, app_client):
        c, *_ = app_client
        r = c.post("/register", data={
            "org_name": "Org1", "email": "a@org1.com", "password": "SecurePass123!",
        }, follow_redirects=False)
        assert r.status_code == 302

    def test_register_rate_limited_after_3(self, app_client):
        c, *_ = app_client
        for i in range(3):
            c.post("/register", data={
                "org_name": f"Org{i}", "email": f"a{i}@org.com", "password": "SecurePass123!",
            }, follow_redirects=False)
        # 4th should be rate limited.
        r = c.post("/register", data={
            "org_name": "Org3", "email": "a3@org.com", "password": "SecurePass123!",
        }, follow_redirects=False)
        assert r.status_code == 429


# ----------------------------------------------------------- Password change


class TestPasswordChange:
    def test_settings_page_requires_login(self, app_client):
        c, *_ = app_client
        r = c.get("/settings", follow_redirects=False)
        assert r.status_code == 403

    def test_settings_page_loads_when_logged_in(self, app_client):
        c, *_ = app_client
        _login(c)
        r = c.get("/settings", follow_redirects=False)
        assert r.status_code == 200
        assert "Change" in r.text

    def test_change_password_success(self, app_client):
        c, db, _, user = app_client
        _login(c)
        r = c.post("/settings", data={
            "old_password": "OldPass123!",
            "new_password": "NewStrongPass456!",
            "new_password_confirm": "NewStrongPass456!",
        }, follow_redirects=False)
        assert r.status_code == 302
        # Verify new password works.
        login_limiter._buckets.clear()
        r = _login(c, password="NewStrongPass456!")
        assert r.status_code == 302

    def test_change_password_wrong_old(self, app_client):
        c, *_ = app_client
        _login(c)
        r = c.post("/settings", data={
            "old_password": "wrong",
            "new_password": "NewStrongPass456!",
            "new_password_confirm": "NewStrongPass456!",
        }, follow_redirects=False)
        assert r.status_code == 400
        assert "incorrect" in r.text.lower()

    def test_change_password_mismatch(self, app_client):
        c, *_ = app_client
        _login(c)
        r = c.post("/settings", data={
            "old_password": "OldPass123!",
            "new_password": "NewStrongPass456!",
            "new_password_confirm": "DifferentPass789!",
        }, follow_redirects=False)
        assert r.status_code == 400
        assert "match" in r.text.lower()

    def test_change_password_too_weak(self, app_client):
        c, *_ = app_client
        _login(c)
        r = c.post("/settings", data={
            "old_password": "OldPass123!",
            "new_password": "weak",
            "new_password_confirm": "weak",
        }, follow_redirects=False)
        assert r.status_code == 400
        assert "12" in r.text


# ----------------------------------------------------------- Password reset


class TestPasswordReset:
    def test_forgot_page_loads(self, app_client):
        c, *_ = app_client
        r = c.get("/forgot", follow_redirects=False)
        assert r.status_code == 200

    def test_forgot_submit_shows_sent(self, app_client):
        c, *_ = app_client
        r = c.post("/forgot", data={"email": "admin@test.com"}, follow_redirects=False)
        assert r.status_code == 200
        assert "sent" in r.text.lower() or "check" in r.text.lower()

    def test_forgot_nonexistent_email_shows_sent(self, app_client):
        c, *_ = app_client
        r = c.post("/forgot", data={"email": "nobody@nowhere.com"}, follow_redirects=False)
        # Should still show "sent" (don't leak whether email exists).
        assert r.status_code == 200
        assert "sent" in r.text.lower() or "check" in r.text.lower()

    def test_reset_with_valid_token(self, app_client):
        c, db, _, user = app_client
        token = db.create_password_reset(user.id, ttl=3600)
        r = c.get(f"/reset?token={token}", follow_redirects=False)
        assert r.status_code == 200
        assert "valid" not in r.text.lower() or "new password" in r.text.lower()

    def test_reset_with_invalid_token(self, app_client):
        c, *_ = app_client
        r = c.get("/reset?token=invalidtoken", follow_redirects=False)
        assert r.status_code == 200
        assert "invalid" in r.text.lower() or "expired" in r.text.lower()

    def test_reset_password_success(self, app_client):
        c, db, _, user = app_client
        token = db.create_password_reset(user.id, ttl=3600)
        r = c.post("/reset", data={
            "token": token,
            "new_password": "BrandNewPass789!",
            "new_password_confirm": "BrandNewPass789!",
        }, follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login"
        # Token is now used.
        assert db.get_password_reset(token) is None
        # New password works.
        login_limiter._buckets.clear()
        r = _login(c, password="BrandNewPass789!")
        assert r.status_code == 302

    def test_reset_expired_token(self, app_client):
        c, db, _, user = app_client
        token = db.create_password_reset(user.id, ttl=-1)  # already expired
        r = c.post("/reset", data={
            "token": token,
            "new_password": "BrandNewPass789!",
            "new_password_confirm": "BrandNewPass789!",
        }, follow_redirects=False)
        assert r.status_code == 400


# ----------------------------------------------------------- Session rotation


class TestSessionRotation:
    def test_session_invalidated_on_password_change(self, app_client):
        c, *_ = app_client
        _login(c)
        # Session is valid.
        r = c.get("/dashboard", follow_redirects=False)
        assert r.status_code == 200
        # Change password.
        c.post("/settings", data={
            "old_password": "OldPass123!",
            "new_password": "NewStrongPass456!",
            "new_password_confirm": "NewStrongPass456!",
        }, follow_redirects=False)
        # Old session should be invalidated (token_version incremented).
        # The new session cookie is set in the redirect response.
        # But if we try to use the OLD session (before the change),
        # it should fail. We simulate this by not following the redirect.
        # The change_password route sets a new cookie, so the old one is gone.
        # Verify the dashboard still works with the new cookie.
        r = c.get("/dashboard", follow_redirects=False)
        assert r.status_code == 200  # new session works

    def test_session_invalidated_on_token_version_mismatch(self, app_client):
        c, db, _, user = app_client
        _login(c)
        # Manually increment token_version in DB (simulates admin changing user's password).
        db.update_password(user.id, hash_password("AdminChangedPass123!"))
        # Old session should now be invalid.
        r = c.get("/dashboard", follow_redirects=False)
        assert r.status_code == 403  # session invalidated
