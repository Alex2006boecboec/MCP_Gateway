"""Ingest API for the cloud dashboard (Phase 5).

POST /api/ingest - the proxy ships audit events here. Validates the API
key, resolves the org, stores events. Idempotent on (org_id, seq).
Rate-limited per key. Never stores secrets (args are already redacted).
"""

from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request, status

from mcp_shield.cloud.db import Database

router = APIRouter(prefix="/api", tags=["ingest"])

# Rate limiting: per-key token bucket (in-memory, MVP).
_MAX_REQUESTS_PER_MINUTE = 100
_MAX_BATCH_SIZE = 100


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


def _resolve_key(db: Database, authorization: Optional[str]) -> tuple[str, list[str]]:
    """Validate the Bearer token and return (org_id, scopes)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization header")
    key = authorization[len("Bearer "):]
    api_key = db.validate_api_key(key)
    if api_key is None:
        raise HTTPException(status_code=401, detail="invalid or revoked API key")
    return api_key.org_id, api_key.scopes


@router.post("/ingest")
async def ingest(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Ingest a batch of audit events from a proxy.

    Body: {"entries": [ <AuditEntry dict>, ... ]}
    Response: 200 {"accepted": N} | 401 | 403 | 413 | 429
    """
    db = _get_db(request)
    org_id, scopes = _resolve_key(db, authorization)

    # Check scope.
    if "ingest" not in scopes:
        raise HTTPException(status_code=403, detail="API key does not have 'ingest' scope")

    # Rate limit.
    if not _limiter.check(org_id):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    # Parse body.
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    if not isinstance(body, dict) or "entries" not in body:
        raise HTTPException(status_code=400, detail="body must have 'entries' list")
    entries = body["entries"]
    if not isinstance(entries, list):
        raise HTTPException(status_code=400, detail="'entries' must be a list")
    if len(entries) > _MAX_BATCH_SIZE:
        raise HTTPException(status_code=413, detail=f"batch too large (max {_MAX_BATCH_SIZE})")

    accepted = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        inserted = db.insert_event(org_id, entry)
        if inserted:
            accepted += 1

    return {"accepted": accepted}


# API v1 alias (versioned endpoint for future compatibility).
@router.post("/v1/ingest")
async def ingest_v1(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Versioned ingest endpoint (alias for /api/ingest)."""
    return await ingest(request, authorization)
