"""Ingest API for the cloud dashboard (Phase 5).

POST /api/ingest     - original endpoint
POST /api/v1/ingest  - versioned endpoint (alias)

Validates the API key, checks scopes, validates input via Pydantic,
rate-limits per key. Never stores secrets (args are already redacted).
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, ValidationError

from mcp_shield.cloud.db import Database

router = APIRouter(prefix="/api", tags=["ingest"])

# Rate limiting: per-key token bucket (in-memory, MVP).
_MAX_REQUESTS_PER_MINUTE = 100
_MAX_BATCH_SIZE = 100
_MAX_BODY_BYTES = 1_000_000  # 1MB
_MAX_STRING_LEN = 500        # individual string fields
_MAX_ARGS_BYTES = 100_000    # args JSON serialized


class IngestEntry(BaseModel):
    """Pydantic model for a single audit event in an ingest batch."""
    seq: int = 0
    ts: str = Field(default="", max_length=_MAX_STRING_LEN)
    decision: str = Field(default="", max_length=50)
    server: str = Field(default="", max_length=_MAX_STRING_LEN)
    tool: str = Field(default="", max_length=_MAX_STRING_LEN)
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=_MAX_STRING_LEN)
    rule: str = Field(default="", max_length=_MAX_STRING_LEN)
    redactions: list[dict[str, Any]] = Field(default_factory=list)
    detection: Optional[dict[str, Any]] = None
    chain: Optional[dict[str, Any]] = None
    approval: Optional[dict[str, Any]] = None

    def to_db_dict(self) -> dict[str, Any]:
        """Convert to dict for db.insert_event()."""
        # Validate args size.
        args_json = json.dumps(self.args, ensure_ascii=False)
        if len(args_json) > _MAX_ARGS_BYTES:
            # Truncate args if too large (defensive).
            self.args = {"_truncated": True, "_original_size": len(args_json)}
        return {
            "seq": self.seq, "ts": self.ts, "decision": self.decision,
            "server": self.server, "tool": self.tool, "args": self.args,
            "reason": self.reason, "rule": self.rule,
            "redactions": self.redactions, "detection": self.detection,
            "chain": self.chain, "approval": self.approval,
        }


class IngestBody(BaseModel):
    """Pydantic model for the ingest request body."""
    entries: list[IngestEntry] = Field(...)  # required, no default


class _RateLimiter:
    """Simple in-memory token bucket per API key. MVP only (single process)."""

    def __init__(self):
        self._buckets: dict[str, list[float]] = {}

    def check(self, key: str) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        now = time.time()
        window = 60.0
        if key not in self._buckets:
            self._buckets[key] = []
        # Drop timestamps older than the window.
        self._buckets[key] = [t for t in self._buckets[key] if now - t < window]
        if len(self._buckets[key]) >= _MAX_REQUESTS_PER_MINUTE:
            return False
        self._buckets[key].append(now)
        return True


_limiter = _RateLimiter()


def _get_db(request: Request) -> Database:
    """Get the Database instance from the app state."""
    db = getattr(request.app.state, "db", None)
    if db is None:
        raise HTTPException(status_code=500, detail="database not configured")
    return db


def _resolve_key(db: Database, authorization: Optional[str]) -> tuple[str, list[str], Any]:
    """Validate the Bearer token and return (org_id, scopes, api_key)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization header")
    key = authorization[len("Bearer "):]
    api_key = db.validate_api_key(key)
    if api_key is None:
        raise HTTPException(status_code=401, detail="invalid or revoked API key")
    return api_key.org_id, api_key.scopes, api_key


def _check_ip_allowed(api_key: Any, request: Request) -> None:
    """Check if the request IP is in the API key's allowed_ips list (if set)."""
    allowed_ips = getattr(api_key, "allowed_ips", None)
    if not allowed_ips:
        return  # no restriction
    client_ip = request.client.host if request.client else ""
    if client_ip and client_ip not in allowed_ips:
        raise HTTPException(status_code=403, detail="IP not allowed for this API key")


async def _do_ingest(request: Request, authorization: Optional[str]) -> dict:
    """Shared ingest logic for both /api/ingest and /api/v1/ingest."""
    db = _get_db(request)
    org_id, scopes, api_key = _resolve_key(db, authorization)

    # Check scope.
    if "ingest" not in scopes:
        raise HTTPException(status_code=403, detail="API key does not have 'ingest' scope")

    # Check IP allowlist.
    _check_ip_allowed(api_key, request)

    # Rate limit.
    if not _limiter.check(org_id):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    # Read body with size check.
    body_bytes = await request.body()
    if len(body_bytes) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail=f"body too large (max {_MAX_BODY_BYTES} bytes)")

    # Parse and validate with Pydantic.
    try:
        raw = json.loads(body_bytes)
        body = IngestBody.model_validate(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    if len(body.entries) > _MAX_BATCH_SIZE:
        raise HTTPException(status_code=413, detail=f"batch too large (max {_MAX_BATCH_SIZE})")

    # Check plan limits: events per month.
    org = db.get_org(org_id)
    if org is not None:
        from mcp_shield.cloud.plans import check_event_limit
        current_count = db.count_events_current_month(org_id)
        allowed, reason = check_event_limit(org.plan, current_count + len(body.entries))
        if not allowed:
            raise HTTPException(status_code=429, detail=f"plan limit exceeded: {reason}")

    accepted = 0
    for entry in body.entries:
        inserted = db.insert_event(org_id, entry.to_db_dict())
        if inserted:
            accepted += 1

    return {"accepted": accepted}


@router.post("/ingest")
async def ingest(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Ingest a batch of audit events from a proxy.

    Body: {"entries": [ <AuditEntry dict>, ... ]}
    Response: 200 {"accepted": N} | 401 | 403 | 413 | 422 | 429
    """
    return await _do_ingest(request, authorization)


# API v1 alias (versioned endpoint for future compatibility).
@router.post("/v1/ingest")
async def ingest_v1(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Versioned ingest endpoint (alias for /api/ingest)."""
    return await _do_ingest(request, authorization)
