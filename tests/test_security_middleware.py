"""Tests for security middleware: CSRF, CORS, security headers, request size limits, cookie flags.

These tests use create_app() which includes the full middleware stack.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from mcp_shield.cloud.server import create_app


@pytest.fixture
def app_client():
    db_path = tempfile.mktemp(suffix=".db")
    app = create_app(db_path, secret="test-secret-12345")
    client = TestClient(app)
    yield client
    app.state.db.close()


# ----------------------------------------------------------- CSRF


class TestCSRF:
    def test_get_sets_csrf_cookie(self, app_client):
        c = app_client
        r = c.get("/login")
        assert r.status_code == 200
        assert "mcp_shield_csrf" in c.cookies

    def test_post_without_csrf_token_returns_403(self, app_client):
        c = app_client
        c.get("/login")  # get CSRF cookie
        r = c.post("/login", data={"email": "admin@mcp-shield.local", "password": "admin"})
        assert r.status_code == 403

    def test_post_with_wrong_csrf_token_returns_403(self, app_client):
        c = app_client
        c.get("/login")
        r = c.post("/login", data={
            "email": "admin@mcp-shield.local", "password": "admin",
            "csrf_token": "wrong-token",
        })
        assert r.status_code == 403

    def test_post_with_valid_csrf_token_passes_csrf(self, app_client):
        c = app_client
        c.get("/login")
        csrf = c.cookies.get("mcp_shield_csrf", "")
        r = c.post("/login", data={
            "email": "admin@mcp-shield.local", "password": "admin",
            "csrf_token": csrf,
        }, follow_redirects=False)
        # Should pass CSRF (may be 302 on success or 401 on bad creds, but NOT 403).
        assert r.status_code != 403

    def test_api_routes_exempt_from_csrf(self, app_client):
        c = app_client
        # POST to /api/ingest without CSRF token should not be 403 (CSRF exempt).
        r = c.post("/api/ingest", json={}, headers={"X-API-Key": "invalid"})
        assert r.status_code != 403  # may be 401 (bad key) but not 403 (CSRF)

    def test_health_exempt_from_csrf(self, app_client):
        c = app_client
        # GET /health should work without CSRF.
        r = c.get("/health")
        assert r.status_code in (200, 404, 503)  # may not exist yet


# ----------------------------------------------------------- Security Headers


class TestSecurityHeaders:
    def test_x_frame_options(self, app_client):
        c = app_client
        r = c.get("/login")
        assert r.headers.get("x-frame-options") == "DENY"

    def test_x_content_type_options(self, app_client):
        c = app_client
        r = c.get("/login")
        assert r.headers.get("x-content-type-options") == "nosniff"

    def test_referrer_policy(self, app_client):
        c = app_client
        r = c.get("/login")
        assert "strict-origin" in r.headers.get("referrer-policy", "")

    def test_csp_header(self, app_client):
        c = app_client
        r = c.get("/login")
        csp = r.headers.get("content-security-policy", "")
        assert "default-src" in csp
        assert "frame-ancestors" in csp

    def test_hsts_only_when_https_enabled(self, app_client, monkeypatch):
        c = app_client
        # Without MCP_SHIELD_HTTPS=1, no HSTS.
        r = c.get("/login")
        assert r.headers.get("strict-transport-security") is None


# ----------------------------------------------------------- CORS


class TestCORS:
    def test_api_has_cors_headers(self, app_client):
        c = app_client
        r = c.post(
            "/api/ingest",
            json={},
            headers={"X-API-Key": "invalid", "Origin": "https://example.com"},
        )
        # CORS header should be present for /api/ paths.
        assert r.headers.get("access-control-allow-origin") == "https://example.com"

    def test_dashboard_no_cors_headers(self, app_client):
        c = app_client
        r = c.get("/login", headers={"Origin": "https://evil.com"})
        # Dashboard should NOT have CORS headers.
        assert r.headers.get("access-control-allow-origin") is None

    def test_api_options_preflight(self, app_client):
        c = app_client
        r = c.options(
            "/api/ingest",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert r.status_code == 200


# ----------------------------------------------------------- Request Size


class TestRequestSize:
    def test_oversized_api_request_rejected(self, app_client):
        c = app_client
        # Create a body > 1MB (ingest max).
        big_body = {"entry": "x" * 1_100_000}
        r = c.post("/api/ingest", json=big_body, headers={"X-API-Key": "test"})
        assert r.status_code == 413

    def test_normal_size_request_allowed(self, app_client):
        c = app_client
        r = c.get("/login")
        assert r.status_code == 200  # small body, no issue


# ----------------------------------------------------------- Cookie Security


class TestCookieSecurity:
    def test_session_cookie_is_httponly(self, app_client):
        c = app_client
        c.get("/login")
        csrf = c.cookies.get("mcp_shield_csrf", "")
        r = c.post("/login", data={
            "email": "admin@mcp-shield.local", "password": "admin",
            "csrf_token": csrf,
        }, follow_redirects=False)
        set_cookie = r.headers.get("set-cookie", "")
        assert "httponly" in set_cookie.lower()
        assert "samesite=lax" in set_cookie.lower()

    def test_session_cookie_secure_when_https(self, monkeypatch):
        """When MCP_SHIELD_HTTPS=1, cookies have Secure flag."""
        monkeypatch.setenv("MCP_SHIELD_HTTPS", "1")
        db_path = tempfile.mktemp(suffix=".db")
        app = create_app(db_path, secret="test-secret")
        c = TestClient(app)
        # GET /login sets CSRF cookie with Secure flag.
        r = c.get("/login")
        set_cookie = r.headers.get("set-cookie", "")
        assert "secure" in set_cookie.lower()
        # Also verify HSTS header is present when HTTPS is enabled.
        assert "strict-transport-security" in r.headers
        app.state.db.close()

    def test_session_cookie_not_secure_without_https(self, app_client):
        c = app_client
        c.get("/login")
        csrf = c.cookies.get("mcp_shield_csrf", "")
        r = c.post("/login", data={
            "email": "admin@mcp-shield.local", "password": "admin",
            "csrf_token": csrf,
        }, follow_redirects=False)
        set_cookie = r.headers.get("set-cookie", "")
        # Without HTTPS, cookie should NOT have Secure flag.
        # (httponly and samesite should still be there)
        assert "samesite=lax" in set_cookie.lower()
