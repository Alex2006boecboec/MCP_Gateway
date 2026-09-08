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

from mcp_shield.cloud.api_ingest import router as ingest_router
from mcp_shield.cloud.auth import SessionManager, hash_password
from mcp_shield.cloud.dashboard import router as dashboard_router
from mcp_shield.cloud.db import Database


def create_app(db_path: str | None = None, secret: str | None = None) -> FastAPI:
    """Create and configure the FastAPI app. Used by tests and the entry point."""
    if db_path is None:
        db_path = os.environ.get("MCP_SHIELD_DB_PATH", "mcp_shield_cloud.db")
    db = Database(db_path)
    app = FastAPI(title="MCP Shield Cloud Dashboard", version="5.0.0")
    app.state.db = db
    app.state.session_manager = SessionManager(secret_key=secret)

    app.include_router(ingest_router)
    app.include_router(dashboard_router)

    _bootstrap(db)
    return app


def _bootstrap(db: Database) -> None:
    """On first run, create a default admin org + user if no org exists."""
    # Check if any org exists.
    row = db._conn.execute("SELECT COUNT(*) as c FROM orgs").fetchone()
    if row and row["c"] > 0:
        return
    org = db.create_org("Default Org")
    db.create_user(org.id, "admin@mcp-shield.local", hash_password("admin"), "admin")
    db.create_api_key(org.id, "default")
    print("=" * 60, file=sys.stderr)
    print("  MCP Shield Cloud - first-run bootstrap complete.", file=sys.stderr)
    print(f"  Default org: {org.name} ({org.id})", file=sys.stderr)
    print("  Admin login: admin@mcp-shield.local / admin", file=sys.stderr)
    print("  CHANGE THE PASSWORD IMMEDIATELY in production!", file=sys.stderr)
    print("=" * 60, file=sys.stderr)


def main():
    """Entry point: run the uvicorn server."""
    import uvicorn

    host = os.environ.get("MCP_SHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("MCP_SHIELD_PORT", "8000"))
    app = create_app()
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
