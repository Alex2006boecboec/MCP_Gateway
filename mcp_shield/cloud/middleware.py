"""Security middleware for the cloud dashboard.

- CSRFMiddleware: double-submit cookie pattern for all state-changing
  form POSTs. API routes (/api/*) are exempt (they use API keys).
- SecurityHeadersMiddleware: X-Frame-Options, X-Content-Type-Options,
  HSTS, Referrer-Policy, CSP.
- RequestSizeLimitMiddleware: reject oversized bodies.
- ApiCorsMiddleware: permissive CORS only for /api/ paths.

All middleware is fail-closed: on any error, the request is rejected.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("mcp_shield.cloud.middleware")

CSRF_COOKIE_NAME = "mcp_shield_csrf"
CSRF_FORM_FIELD = "csrf_token"

# Safe methods that don't need CSRF protection.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

# Paths exempt from CSRF (API uses API keys, not cookies).
CSRF_EXEMPT_PREFIXES = ("/api/", "/health")


def _is_https_enabled() -> bool:
    return os.environ.get("MCP_SHIELD_HTTPS", "") == "1"


def _get_secret(request: Request) -> str:
    sm = getattr(request.app.state, "session_manager", None)
    if sm is not None:
        return sm.secret_key or "fallback-csrf-secret"
    return "fallback-csrf-secret"


def _sign_token(token: str, secret: str) -> str:
    """Sign a token with the secret using HMAC-SHA256. Returns token.signature."""
    import hashlib

    sig = hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{sig}"


def _verify_token(signed: str, secret: str) -> bool:
    """Verify a signed token. Returns True if valid."""
    if not signed or "." not in signed:
        return False
    token, sig = signed.rsplit(".", 1)
    expected = _sign_token(token, secret)
    return hmac.compare_digest(signed, expected)


def _generate_csrf_token(secret: str) -> str:
    """Generate a random token signed with the secret."""
    token = secrets.token_urlsafe(32)
    return _sign_token(token, secret)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF protection.

    On any GET, a signed CSRF token is set as a cookie (if not present).
    On POST/PUT/DELETE to non-exempt paths, the form field `csrf_token`
    must match the cookie. API routes are exempt (they use API keys).
    """

    async def dispatch(self, request: Request, call_next):
        secret = _get_secret(request)
        path = request.url.path

        # Generate/refresh cookie on safe methods.
        if request.method in SAFE_METHODS:
            response = await call_next(request)
            existing = request.cookies.get(CSRF_COOKIE_NAME)
            if existing is None or not _verify_token(existing, secret):
                token = _generate_csrf_token(secret)
                response.set_cookie(
                    CSRF_COOKIE_NAME,
                    token,
                    httponly=False,  # JS needs to read it for AJAX forms
                    samesite="lax",
                    secure=_is_https_enabled(),
                    max_age=365 * 24 * 3600,
                    path="/",
                )
            return response

        # Non-safe method: check CSRF unless exempt.
        if any(path.startswith(p) for p in CSRF_EXEMPT_PREFIXES):
            return await call_next(request)

        # Verify double-submit: cookie == form field.
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        if cookie_token is None or not _verify_token(cookie_token, secret):
            logger.warning("CSRF: missing or invalid cookie token for %s %s", request.method, path)
            return _csrf_error("CSRF validation failed")

        # Read the body so we can both check CSRF and re-inject it for the handler.
        body = await request.body()
        content_type = request.headers.get("content-type", "")

        # Parse form data from the body.
        from starlette.datastructures import FormData

        form_token = ""
        if content_type.startswith("application/x-www-form-urlencoded"):
            from urllib.parse import parse_qs

            parsed = parse_qs(body.decode("utf-8", errors="replace"))
            form_token = parsed.get(CSRF_FORM_FIELD, [""])[0]
        elif content_type.startswith("multipart/form-data"):
            # For multipart, use Starlette's form parser.
            # Re-inject body first, then parse.
            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = receive
            form = await request.form()
            form_token = str(form.get(CSRF_FORM_FIELD, ""))
            # Re-inject body again for the handler.
            async def receive2():
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = receive2
            # Clear cached form so handler re-parses.
            if hasattr(request, "_form"):
                delattr(request, "_form")
        else:
            # Non-form POST (e.g., JSON API) — allow if not a form.
            # Re-inject body.
            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = receive
            return await call_next(request)

        if not form_token or not hmac.compare_digest(cookie_token, form_token):
            logger.warning("CSRF: token mismatch for %s %s", request.method, path)
            return _csrf_error("CSRF validation failed")

        # Re-inject body so the handler can read the form again.
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive
        # Clear cached form so handler re-parses from re-injected body.
        if hasattr(request, "_form"):
            delattr(request, "_form")
        return await call_next(request)


def _csrf_error(message: str) -> Response:
    return Response(
        content=f'<html><body><h1>403 Forbidden</h1><p>{message}</p>'
               f'<p><a href="/dashboard">Back to dashboard</a></p></body></html>',
        status_code=403,
        media_type="text/html",
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # CSP: allow inline styles (templates use <style>), self for everything else.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        if _is_https_enabled():
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with bodies larger than max_bytes."""

    def __init__(self, app, default_max: int = 2_000_000, ingest_max: int = 1_000_000):
        super().__init__(app)
        self.default_max = default_max
        self.ingest_max = ingest_max

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        max_bytes = self.ingest_max if path.startswith("/api/") else self.default_max
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
            except ValueError:
                return JSONResponse({"detail": "invalid content-length"}, status_code=400)
            if size > max_bytes:
                logger.warning("request too large: %d > %d for %s", size, max_bytes, path)
                return JSONResponse(
                    {"detail": f"request body too large (max {max_bytes} bytes)"},
                    status_code=413,
                )
        return await call_next(request)


class ApiCorsMiddleware(BaseHTTPMiddleware):
    """Permissive CORS only for /api/ paths. Dashboard gets no CORS headers."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        origin = request.headers.get("origin")
        path = request.url.path

        if origin and path.startswith("/api/"):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Key"
            response.headers["Access-Control-Max-Age"] = "3600"
            # Don't allow credentials cross-origin (API uses keys, not cookies).
            response.headers["Access-Control-Allow-Credentials"] = "false"

        # Handle preflight OPTIONS.
        if request.method == "OPTIONS" and path.startswith("/api/"):
            response.status_code = 200

        return response
