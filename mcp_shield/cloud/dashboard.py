"""Dashboard routes for the cloud server (Phase 5).

Server-rendered HTML via Jinja2. All routes require a logged-in session
(except /login). RBAC enforced per route. Every query is scoped by the
session user's org_id (multi-tenant isolation).
"""

from __future__ import annotations

import os
import time
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from mcp_shield.cloud.auth import SessionManager, hash_password, verify_password
from mcp_shield.cloud.db import Database
from mcp_shield.cloud.middleware import CSRF_COOKIE_NAME
from mcp_shield.cloud.passwords import validate_password
from mcp_shield.cloud.rbac import can
from mcp_shield.cloud.rate_limit import (
    check_forgot_allowed,
    check_login_allowed,
    check_register_allowed,
    get_login_delay,
    record_login_failure,
    record_login_success,
)
from mcp_shield.cloud.reports import FRAMEWORKS, generate_report, report_to_csv

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="mcp_shield/cloud/templates")

COOKIE_NAME = "mcp_shield_session"

# Simple email regex (good enough for input validation; the real check is
# whether we can send mail, but we don't have an email service yet).
import re as _re
_EMAIL_RE = _re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _is_valid_email(email: str) -> bool:
    """Return True if email looks like a valid address."""
    return bool(_EMAIL_RE.match(email.strip()))


@router.get("/health")
def health_check(request: Request):
    """Health check endpoint. No auth required. Returns 200 or 503."""
    db = _get_db(request)
    try:
        if db.health_check():
            from fastapi.responses import JSONResponse
            return JSONResponse({"status": "ok", "database": "connected"})
        else:
            from fastapi.responses import JSONResponse
            return JSONResponse({"status": "error", "detail": "database unreachable"}, status_code=503)
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse({"status": "error", "detail": str(e)}, status_code=503)


def _is_https() -> bool:
    return os.environ.get("MCP_SHIELD_HTTPS", "") == "1"


def _set_session_cookie(resp: Response, token: str) -> None:
    """Set session cookie with security flags."""
    resp.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=_is_https(),
        max_age=7 * 24 * 3600,
        path="/",
    )


def _base_context(request: Request, session: Optional[dict] = None) -> dict:
    """Common template context with CSRF token."""
    ctx = {"session": session}
    ctx["csrf_token"] = request.cookies.get(CSRF_COOKIE_NAME, "")
    return ctx


# ----------------------------------------------------------- dependencies


def _get_db(request: Request) -> Database:
    db = getattr(request.app.state, "db", None)
    if db is None:
        raise HTTPException(status_code=500, detail="database not configured")
    return db


def _get_session(request: Request) -> Optional[dict]:
    """Read and verify the session cookie. Returns the payload or None."""
    sm: SessionManager = getattr(request.app.state, "session_manager", None)
    if sm is None:
        return None
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    payload = sm.verify_session(cookie)
    if payload is None:
        return None
    # Verify token_version against DB (session rotation).
    db = getattr(request.app.state, "db", None)
    if db is not None and "user_id" in payload:
        user = db.get_user(payload["user_id"])
        if user is None or user.deleted:
            return None  # user deleted or soft-deleted
        if "token_version" in payload and payload["token_version"] != user.token_version:
            return None  # session invalidated by password/role change
        # Carry must_change_password flag so _require_user can enforce it.
        payload["must_change_password"] = user.must_change_password
    return payload


def _require_user(request: Request) -> dict:
    """Require a logged-in user. Raises 403 if not logged in.
    If the user must change their password, redirect to /settings
    (unless they're already on /settings or /logout)."""
    session = _get_session(request)
    if session is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="not logged in")
    # Enforce must_change_password on every page except /settings and /logout.
    if session.get("must_change_password") and request.url.path not in ("/settings", "/logout"):
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            detail="password change required",
            headers={"Location": "/settings?force=1"},
        )
    return session


def _require_role(request: Request, action: str) -> dict:
    """Require a user whose role can perform `action`. Raises 403."""
    session = _require_user(request)
    if not can(session.get("role", ""), action):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
    return session


# ----------------------------------------------------------- routes


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    session = _get_session(request)
    if session is None:
        return RedirectResponse("/login", status_code=302)
    return RedirectResponse("/dashboard", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", _base_context(request) | {"error": None})


@router.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    db = _get_db(request)
    ip = request.client.host if request.client else "unknown"

    # Rate limit check.
    allowed, reason = check_login_allowed(email, ip)
    if not allowed:
        return templates.TemplateResponse(request, "login.html",
            _base_context(request) | {"error": reason}, status_code=429)

    user = db.get_user_by_email(email)
    if user is None or not verify_password(password, user.password_hash or ""):
        record_login_failure(email)
        # Add delay to slow down brute force.
        delay = get_login_delay(email)
        if delay > 0:
            time.sleep(min(delay, 10))
        return templates.TemplateResponse(request, "login.html",
            _base_context(request) | {"error": "Invalid email or password"}, status_code=401)

    record_login_success(email)
    sm: SessionManager = request.app.state.session_manager
    token = sm.create_session(user, token_version=user.token_version)

    # If must_change_password, redirect to /settings (with session cookie set).
    if user.must_change_password:
        resp = RedirectResponse("/settings?force=1", status_code=302)
    else:
        resp = RedirectResponse("/dashboard", status_code=302)
    _set_session_cookie(resp, token)
    return resp


@router.get("/logout")
def logout(request: Request):
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    return resp


@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse(request, "register.html", _base_context(request) | {"error": None})


@router.post("/register")
async def register(
    request: Request,
    org_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    """Self-service registration: create a new org + admin user."""
    db = _get_db(request)
    ip = request.client.host if request.client else "unknown"

    # Rate limit check.
    allowed, reason = check_register_allowed(ip)
    if not allowed:
        return templates.TemplateResponse(request, "register.html",
            _base_context(request) | {"error": reason}, status_code=429)

    # Check if email already exists.
    if db.get_user_by_email(email) is not None:
        return templates.TemplateResponse(request, "register.html",
            _base_context(request) | {"error": "Email already registered. Use /login instead."}, status_code=400)

    # Validate email format.
    if not _is_valid_email(email):
        return templates.TemplateResponse(request, "register.html",
            _base_context(request) | {"error": "Invalid email format."}, status_code=400)

    # Validate password strength.
    pw_errors = validate_password(password)
    if pw_errors:
        return templates.TemplateResponse(request, "register.html",
            _base_context(request) | {"error": " ".join(pw_errors)}, status_code=400)

    if not org_name.strip():
        return templates.TemplateResponse(request, "register.html",
            _base_context(request) | {"error": "Organization name is required."}, status_code=400)
    org_name = org_name.strip()[:100]  # limit length

    # Create org + admin user.
    org = db.create_org(org_name)
    user = db.create_user(org.id, email, hash_password(password), "admin")
    # Auto-create a default API key.
    db.create_api_key(org.id, "default")
    # Log them in.
    sm: SessionManager = request.app.state.session_manager
    token = sm.create_session(user, token_version=user.token_version)
    resp = RedirectResponse("/dashboard", status_code=302)
    _set_session_cookie(resp, token)
    return resp


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    decision: Optional[str] = None,
    server: Optional[str] = None,
    tool: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    page: int = 1,
):
    session = _require_user(request)
    db = _get_db(request)
    org_id = session["org_id"]
    limit = 50
    page = max(1, page)  # prevent negative/zero offset (Postgres errors on negative OFFSET)
    offset = (page - 1) * limit
    events = db.query_events(org_id, decision=decision, server=server, tool=tool,
                              start=start, end=end, limit=limit, offset=offset)
    summary = db.summary(org_id, start=start, end=end)
    return templates.TemplateResponse(request, "dashboard.html", _base_context(request, session) | {
        "events": events,
        "summary": summary,
        "filters": {"decision": decision or "", "server": server or "", "tool": tool or "",
                    "start": start or "", "end": end or ""},
        "page": page,
        "has_next": len(events) == limit,
    })


@router.get("/events/{event_id}", response_class=HTMLResponse)
def event_detail(request: Request, event_id: int):
    session = _require_user(request)
    db = _get_db(request)
    ev = db.get_event(session["org_id"], event_id)
    if ev is None:
        raise HTTPException(status_code=404, detail="event not found")
    return templates.TemplateResponse(request, "event_detail.html", _base_context(request, session) | {"event": ev})


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    session = _require_role(request, "view_reports")
    return templates.TemplateResponse(request, "reports.html", _base_context(request, session) | {
        "frameworks": FRAMEWORKS,
    })


@router.get("/reports/{framework}", response_class=HTMLResponse)
def view_report(
    request: Request,
    framework: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    session = _require_role(request, "view_reports")
    db = _get_db(request)
    try:
        report = generate_report(db, session["org_id"], framework, start, end)
    except ValueError:
        raise HTTPException(status_code=404, detail="unknown report framework")
    return templates.TemplateResponse(request, "report_view.html", _base_context(request, session) | {
        "report": report,
    })


@router.get("/reports/{framework}/download")
def download_report(
    request: Request,
    framework: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    session = _require_role(request, "view_reports")
    db = _get_db(request)
    try:
        report = generate_report(db, session["org_id"], framework, start, end)
    except ValueError:
        raise HTTPException(status_code=404, detail="unknown report framework")
    csv = report_to_csv(report)
    return Response(content=csv, media_type="text/csv",
                     headers={"Content-Disposition": f"attachment; filename={framework}_report.csv"})


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    session = _require_role(request, "manage_users")
    db = _get_db(request)
    users = db.list_users(session["org_id"])
    return templates.TemplateResponse(request, "users.html", _base_context(request, session) | {"users": users})


@router.post("/users")
async def create_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
):
    session = _require_role(request, "manage_users")
    db = _get_db(request)
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="invalid role")
    # Validate email format.
    if not _is_valid_email(email):
        raise HTTPException(status_code=400, detail="invalid email format")
    # Validate password strength.
    pw_errors = validate_password(password)
    if pw_errors:
        raise HTTPException(status_code=400, detail=" ".join(pw_errors))
    try:
        user = db.create_user(session["org_id"], email, hash_password(password), role)
        db.log_action(session["org_id"], session["user_id"], session.get("email", ""),
                       "user.create", "user", user.id, f"email={email}, role={role}")
    except Exception:
        raise HTTPException(status_code=400, detail="email already exists")
    return RedirectResponse("/users", status_code=302)


@router.post("/users/{user_id}/delete")
async def delete_user(request: Request, user_id: str):
    session = _require_role(request, "manage_users")
    db = _get_db(request)
    # Can't delete self.
    if user_id == session["user_id"]:
        raise HTTPException(status_code=400, detail="cannot delete your own account")
    # Check user exists and belongs to same org.
    target = db.get_user(user_id)
    if target is None or target.org_id != session["org_id"]:
        raise HTTPException(status_code=404, detail="user not found")
    # Can't delete last admin.
    if target.role == "admin" and db.count_admins(session["org_id"]) <= 1:
        raise HTTPException(status_code=400, detail="cannot delete the last admin")
    db.delete_user(user_id)
    db.log_action(session["org_id"], session["user_id"], session.get("email", ""),
                   "user.delete", "user", user_id, f"email={target.email}")
    return RedirectResponse("/users", status_code=302)


@router.post("/users/{user_id}/role")
async def change_role(request: Request, user_id: str, role: str = Form(...)):
    session = _require_role(request, "manage_users")
    db = _get_db(request)
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="invalid role")
    # Can't change own role (prevent self-demotion).
    if user_id == session["user_id"]:
        raise HTTPException(status_code=400, detail="cannot change your own role")
    target = db.get_user(user_id)
    if target is None or target.org_id != session["org_id"]:
        raise HTTPException(status_code=404, detail="user not found")
    # Can't demote last admin.
    if target.role == "admin" and role != "admin" and db.count_admins(session["org_id"]) <= 1:
        raise HTTPException(status_code=400, detail="cannot demote the last admin")
    db.update_user_role(user_id, role)
    db.log_action(session["org_id"], session["user_id"], session.get("email", ""),
                   "user.role_change", "user", user_id, f"from={target.role}, to={role}")
    return RedirectResponse("/users", status_code=302)


@router.get("/keys", response_class=HTMLResponse)
def keys_page(request: Request):
    session = _require_role(request, "manage_keys")
    db = _get_db(request)
    keys = db.list_api_keys(session["org_id"])
    return templates.TemplateResponse(request, "keys.html", _base_context(request, session) | {"keys": keys})


@router.post("/keys")
async def create_key(
    request: Request,
    label: str = Form(...),
    scopes: str = Form("ingest"),
):
    session = _require_role(request, "manage_keys")
    db = _get_db(request)
    label = label.strip()[:100]  # limit length
    if not label:
        raise HTTPException(status_code=400, detail="label is required")
    # Parse scopes.
    scope_list = [s.strip() for s in scopes.split(",") if s.strip() in ("ingest", "read")]
    if not scope_list:
        scope_list = ["ingest"]
    key = db.create_api_key(session["org_id"], label, scopes=scope_list)
    db.log_action(session["org_id"], session["user_id"], session.get("email", ""),
                   "key.create", "api_key", key.key, f"label={label}, scopes={scope_list}")
    return RedirectResponse("/keys", status_code=302)


@router.post("/keys/{key}/revoke")
async def revoke_key(request: Request, key: str):
    session = _require_role(request, "manage_keys")
    db = _get_db(request)
    # Verify the key belongs to this org (prevent cross-org IDOR).
    api_key = db.validate_api_key(key)
    if api_key is None or api_key.org_id != session["org_id"]:
        raise HTTPException(status_code=404, detail="key not found")
    db.revoke_api_key(key)
    db.log_action(session["org_id"], session["user_id"], session.get("email", ""),
                   "key.revoke", "api_key", key, "")
    return RedirectResponse("/keys", status_code=302)


# ----------------------------------------------------------- audit log


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, page: int = 1):
    session = _require_role(request, "manage_users")
    db = _get_db(request)
    limit = 100
    page = max(1, page)  # prevent negative/zero offset
    offset = (page - 1) * limit
    actions = db.query_actions(session["org_id"], limit=limit, offset=offset)
    return templates.TemplateResponse(request, "audit.html",
        _base_context(request, session) | {"actions": actions, "page": page})


# ----------------------------------------------------------- settings (password change)


@router.get("/settings", response_class=HTMLResponse)
def settings_form(request: Request, force: Optional[str] = None):
    session = _require_user(request)
    return templates.TemplateResponse(request, "settings.html",
        _base_context(request, session) | {"error": None, "force": force == "1"})


@router.post("/settings")
async def change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
):
    session = _require_user(request)
    db = _get_db(request)
    user = db.get_user(session["user_id"])
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")

    # Verify old password.
    if not verify_password(old_password, user.password_hash or ""):
        return templates.TemplateResponse(request, "settings.html",
            _base_context(request, session) | {"error": "Current password is incorrect.", "force": False},
            status_code=400)

    # Validate new password.
    pw_errors = validate_password(new_password)
    if pw_errors:
        return templates.TemplateResponse(request, "settings.html",
            _base_context(request, session) | {"error": " ".join(pw_errors), "force": False},
            status_code=400)

    # Confirm match.
    if new_password != new_password_confirm:
        return templates.TemplateResponse(request, "settings.html",
            _base_context(request, session) | {"error": "New passwords do not match.", "force": False},
            status_code=400)

    # Update password (increments token_version, clears must_change_password).
    db.update_password(user.id, hash_password(new_password))

    # Re-create session with new token_version.
    updated_user = db.get_user(user.id)
    if updated_user is not None:
        sm: SessionManager = request.app.state.session_manager
        token = sm.create_session(updated_user, token_version=updated_user.token_version)
        resp = RedirectResponse("/dashboard", status_code=302)
        _set_session_cookie(resp, token)
        return resp
    return RedirectResponse("/dashboard", status_code=302)


# ----------------------------------------------------------- password reset


@router.get("/forgot", response_class=HTMLResponse)
def forgot_form(request: Request):
    return templates.TemplateResponse(request, "forgot.html",
        _base_context(request) | {"error": None, "sent": False})


@router.post("/forgot")
async def forgot_password(
    request: Request,
    email: str = Form(...),
):
    db = _get_db(request)
    ip = request.client.host if request.client else "unknown"
    allowed, reason = check_forgot_allowed(email, ip)
    if not allowed:
        return templates.TemplateResponse(request, "forgot.html",
            _base_context(request) | {"error": reason, "sent": False}, status_code=429)

    user = db.get_user_by_email(email)
    if user is not None:
        # Generate reset token (TTL 1 hour).
        token = db.create_password_reset(user.id, ttl=3600)
        # Send reset email via SMTP (or log in dev mode).
        from mcp_shield.cloud.email import get_email_service
        email_service = get_email_service()
        sent = email_service.send_password_reset(email, token)
        # Log only a truncated hint (never the full token). Never surface
        # SMTP failure to the client (would confirm the account exists).
        import logging
        logging.getLogger("mcp_shield.cloud").info(
            "password reset token generated for %s (token prefix: %s..., sent=%s)",
            email, token[:8], sent,
        )
    # Always show "sent" message (don't leak whether email exists).
    return templates.TemplateResponse(request, "forgot.html",
        _base_context(request) | {"error": None, "sent": True})


@router.get("/reset", response_class=HTMLResponse)
def reset_form(request: Request, token: Optional[str] = None):
    db = _get_db(request)
    valid = False
    if token:
        reset = db.get_password_reset(token)
        valid = reset is not None
    return templates.TemplateResponse(request, "reset.html",
        _base_context(request) | {"token": token or "", "valid": valid, "error": None})


@router.post("/reset")
async def reset_password(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
):
    db = _get_db(request)
    reset = db.get_password_reset(token)
    if reset is None:
        return templates.TemplateResponse(request, "reset.html",
            _base_context(request) | {"token": token, "valid": False,
            "error": "Invalid or expired reset token."}, status_code=400)

    # Validate new password.
    pw_errors = validate_password(new_password)
    if pw_errors:
        return templates.TemplateResponse(request, "reset.html",
            _base_context(request) | {"token": token, "valid": True,
            "error": " ".join(pw_errors)}, status_code=400)

    if new_password != new_password_confirm:
        return templates.TemplateResponse(request, "reset.html",
            _base_context(request) | {"token": token, "valid": True,
            "error": "Passwords do not match."}, status_code=400)

    # Update password and invalidate token.
    db.update_password(reset["user_id"], hash_password(new_password))
    db.use_password_reset(token)

    return RedirectResponse("/login", status_code=302)


# ----------------------------------------------------------- GDPR: export & delete


@router.get("/org/export")
def export_org_data(request: Request):
    """Export all org data as a JSON file (GDPR right to data portability)."""
    session = _require_role(request, "manage_users")
    db = _get_db(request)
    org_id = session["org_id"]
    org = db.get_org(org_id)
    users = db.list_users(org_id)
    keys = db.list_api_keys(org_id)
    events = db.query_events(org_id, limit=10000)
    actions = db.query_actions(org_id, limit=10000)

    data = {
        "org": {"id": org.id, "name": org.name, "created_at": org.created_at} if org else None,
        "users": [{"id": u.id, "email": u.email, "role": u.role, "created_at": u.created_at} for u in users],
        "api_keys": [{"key": k.key[:20] + "...", "label": k.label, "scopes": k.scopes,
                      "revoked": k.revoked, "created_at": k.created_at} for k in keys],
        "events": [{"id": e.id, "seq": e.seq, "ts": e.ts, "decision": e.decision,
                    "server": e.server, "tool": e.tool, "reason": e.reason} for e in events],
        "actions": actions,
    }
    import json
    content = json.dumps(data, indent=2, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="org_{org_id[:8]}_export.json"'},
    )


@router.post("/org/delete")
async def delete_org(
    request: Request,
    confirm: str = Form(...),
):
    """Delete all org data (GDPR right to erasure). Requires typing 'DELETE' to confirm."""
    session = _require_role(request, "manage_users")
    db = _get_db(request)
    if confirm != "DELETE":
        raise HTTPException(status_code=400, detail="Type DELETE to confirm")
    org_id = session["org_id"]
    db.log_action(org_id, session["user_id"], session.get("email", ""),
                   "org.delete", "org", org_id, "GDPR erasure")
    db.delete_org_data(org_id)
    # Logout (org is gone, session invalid).
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    return resp


# ----------------------------------------------------------- subscription plans

@router.get("/plans", response_class=HTMLResponse)
def plans_page(request: Request):
    """Show available subscription plans and current plan."""
    import os
    session = _require_user(request)
    db = _get_db(request)
    org = db.get_org(session["org_id"])
    from mcp_shield.cloud.plans import PLANS, get_plan
    current_plan = get_plan(org.plan if org else "free")
    # Calculate current month usage.
    usage = db.count_events_current_month(session["org_id"])
    allow_self_upgrade = os.environ.get("MCP_SHIELD_ALLOW_SELF_UPGRADE", "").lower() in ("1", "true", "yes")
    return templates.TemplateResponse(request, "plans.html",
        _base_context(request, session) | {
            "plans": PLANS,
            "current_plan": current_plan,
            "usage": usage,
            "allow_self_upgrade": allow_self_upgrade,
        })


@router.post("/plans/upgrade")
def upgrade_plan(
    request: Request,
    plan: str = Form(...),
):
    """Upgrade the org's plan (admin only).

    Self-serve upgrades are disabled unless MCP_SHIELD_ALLOW_SELF_UPGRADE=1,
    because there is no payment integration yet — otherwise free→enterprise
    would be a single form POST.
    """
    import os
    if os.environ.get("MCP_SHIELD_ALLOW_SELF_UPGRADE", "").lower() not in ("1", "true", "yes"):
        raise HTTPException(
            status_code=403,
            detail="Self-serve plan upgrades are disabled. Set MCP_SHIELD_ALLOW_SELF_UPGRADE=1 "
                   "for demos, or contact sales for a paid plan.",
        )
    session = _require_role(request, "manage_org")
    db = _get_db(request)
    from mcp_shield.cloud.plans import PLANS, can_upgrade_to
    if plan not in PLANS:
        raise HTTPException(status_code=400, detail="invalid plan")
    org_id = session["org_id"]
    org = db.get_org(org_id)
    current = org.plan if org else "free"
    if not can_upgrade_to(current, plan):
        raise HTTPException(status_code=400, detail="can only upgrade to a higher plan")
    db.update_org_plan(org_id, plan)
    db.log_action(org_id, session["user_id"], session.get("email", ""),
                   "plan.upgrade", "org", org_id, f"{current} -> {plan}")
    return RedirectResponse("/plans", status_code=302)
