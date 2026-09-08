"""Dashboard routes for the cloud server (Phase 5).

Server-rendered HTML via Jinja2. All routes require a logged-in session
(except /login). RBAC enforced per route. Every query is scoped by the
session user's org_id (multi-tenant isolation).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from mcp_shield.cloud.auth import SessionManager, hash_password, verify_password
from mcp_shield.cloud.db import Database
from mcp_shield.cloud.rbac import can
from mcp_shield.cloud.reports import FRAMEWORKS, generate_report, report_to_csv

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="mcp_shield/cloud/templates")

COOKIE_NAME = "mcp_shield_session"


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
    return sm.verify_session(cookie) if cookie else None


def _require_user(request: Request) -> dict:
    """Require a logged-in user. Raises 401 -> redirect to /login."""
    session = _get_session(request)
    if session is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="not logged in")
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
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    db = _get_db(request)
    user = db.get_user_by_email(email)
    if user is None or not verify_password(password, user.password_hash or ""):
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid email or password"}, status_code=401)
    sm: SessionManager = request.app.state.session_manager
    token = sm.create_session(user)
    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, max_age=7 * 24 * 3600)
    return resp


@router.get("/logout")
def logout(request: Request):
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
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
    offset = (page - 1) * limit
    events = db.query_events(org_id, decision=decision, server=server, tool=tool,
                              start=start, end=end, limit=limit, offset=offset)
    summary = db.summary(org_id, start=start, end=end)
    return templates.TemplateResponse(request, "dashboard.html", {
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
    return templates.TemplateResponse(request, "event_detail.html", {"event": ev})


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    session = _require_role(request, "view_reports")
    return templates.TemplateResponse(request, "reports.html", {
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
    report = generate_report(db, session["org_id"], framework, start, end)
    return templates.TemplateResponse(request, "report_view.html", {
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
    report = generate_report(db, session["org_id"], framework, start, end)
    csv = report_to_csv(report)
    return Response(content=csv, media_type="text/csv",
                     headers={"Content-Disposition": f"attachment; filename={framework}_report.csv"})


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    session = _require_role(request, "manage_users")
    db = _get_db(request)
    users = db.list_users(session["org_id"])
    return templates.TemplateResponse(request, "users.html", {"users": users})


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
    try:
        db.create_user(session["org_id"], email, hash_password(password), role)
    except Exception:
        raise HTTPException(status_code=400, detail="email already exists")
    return RedirectResponse("/users", status_code=302)


@router.get("/keys", response_class=HTMLResponse)
def keys_page(request: Request):
    session = _require_role(request, "manage_keys")
    db = _get_db(request)
    keys = db.list_api_keys(session["org_id"])
    return templates.TemplateResponse(request, "keys.html", {"keys": keys})


@router.post("/keys")
async def create_key(
    request: Request,
    label: str = Form(...),
):
    session = _require_role(request, "manage_keys")
    db = _get_db(request)
    key = db.create_api_key(session["org_id"], label)
    return RedirectResponse("/keys", status_code=302)


@router.post("/keys/{key}/revoke")
async def revoke_key(request: Request, key: str):
    session = _require_role(request, "manage_keys")
    db = _get_db(request)
    db.revoke_api_key(key)
    return RedirectResponse("/keys", status_code=302)
