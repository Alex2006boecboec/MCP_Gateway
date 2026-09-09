"""FastAPI app assembly + entry point for the cloud dashboard (Phase 5).

Run:  python -m mcp_shield.cloud.server
  or: mcp-shield-cloud  (console script, installed via [cloud] extra)

Env vars:
  MCP_SHIELD_DB_PATH      - SQLite file path (default: mcp_shield_cloud.db)
  MCP_SHIELD_SESSION_SECRET - session cookie signing key (auto-generated if unset)
  MCP_SHIELD_HOST         - bind host (default: 127.0.0.1)
  MCP_SHIELD_PORT         - bind port (default: 8000)

On first run, if the DB is empty, a default admin org + user is created:
  email: admin@mcp-shield.local
  password: admin  (CHANGE IMMEDIATELY in production!)
"""

from __future__ import annotations

import os
import sys

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from mcp_shield.cloud.api_ingest import router as ingest_router
from mcp_shield.cloud.auth import SessionManager, hash_password
from mcp_shield.cloud.dashboard import router as dashboard_router
from mcp_shield.cloud.middleware import (
    ApiCorsMiddleware,
    CSRFMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from mcp_shield.cloud.storage_factory import create_storage


def create_app(db_path: str | None = None, secret: str | None = None) -> FastAPI:
    """Create and configure the FastAPI app. Used by tests and the entry point.

    If db_path is given (tests), uses SQLite. Otherwise picks backend
    from env DATABASE_URL (Postgres on Railway) or MCP_SHIELD_DB_PATH.
    """
    db = create_storage(db_path)
    app = FastAPI(title="MCP Shield Cloud Dashboard", version="5.4.0")
    app.state.db = db
    app.state.session_manager = SessionManager(secret_key=secret)

    # Middleware order: outermost first (executed last on response).
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(ApiCorsMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware, default_max=2_000_000, ingest_max=1_000_000)
    app.add_middleware(CSRFMiddleware)

    app.include_router(ingest_router)
    app.include_router(dashboard_router)

    _bootstrap(db)
    _start_retention_task(db)
    return app


def _start_retention_task(db) -> None:
    """Start a background thread that periodically deletes old events.

    Runs every hour. Retention period from MCP_SHIELD_RETENTION_DAYS env
    (default 90 days). Disabled if MCP_SHIELD_RETENTION_DAYS=0.
    """
    import logging
    import threading

    logger = logging.getLogger("mcp_shield.cloud.retention")

    def _retention_loop():
        import time
        while True:
            try:
                days = int(os.environ.get("MCP_SHIELD_RETENTION_DAYS", "90"))
                if days > 0:
                    deleted = db.delete_old_events(days)
                    if deleted > 0:
                        logger.info("retention: deleted %d events older than %d days", deleted, days)
            except Exception as e:
                logger.error("retention task error: %s", e)
            time.sleep(3600)  # 1 hour

    thread = threading.Thread(target=_retention_loop, daemon=True, name="retention")
    thread.start()


def _bootstrap(db) -> None:
    """On first run, create a default admin org + user if no org exists."""
    # Check if any org exists (uses Storage protocol, works for SQLite + Postgres).
    if db.count_orgs() > 0:
        return
    org = db.create_org("Default Org")
    # Create admin with must_change_password=True to force a password change
    # on first login (the default password "admin" is weak).
    admin = db.create_user(org.id, "admin@mcp-shield.local", hash_password("admin"), "admin", must_change_password=True)
    db.create_api_key(org.id, "default")
    print("=" * 60, file=sys.stderr)
    print("  MCP Shield Cloud - first-run bootstrap complete.", file=sys.stderr)
    print(f"  Default org: {org.name} ({org.id})", file=sys.stderr)
    print("  Admin login: admin@mcp-shield.local / admin", file=sys.stderr)
    print("  You will be REQUIRED to change this password on first login.", file=sys.stderr)
    print("=" * 60, file=sys.stderr)


def main():
    """Entry point: run the uvicorn server.

    Railway provides PORT; we also check MCP_SHIELD_PORT for local runs.
    """
    import uvicorn

    host = os.environ.get("MCP_SHIELD_HOST", "0.0.0.0")
    # Railway sets PORT; prefer it over MCP_SHIELD_PORT.
    port = int(os.environ.get("PORT") or os.environ.get("MCP_SHIELD_PORT") or "8000")
    app = create_app()
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
