"""Storage factory: picks the right backend based on env vars.

  DATABASE_URL / MCP_SHIELD_DB_URL set to a postgres:// URL  -> PostgresStorage
  Otherwise                                                 -> SqliteStorage

This lets the same code run on Railway (Postgres) and in tests (SQLite)
without any code changes.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from mcp_shield.cloud.storage import Storage

logger = logging.getLogger("mcp_shield.cloud.factory")


def create_storage(db_path: str | None = None) -> Storage:
    """Create a Storage backend based on environment variables.

    Priority:
      1. Explicit db_path argument (used by tests)
      2. DATABASE_URL env (Railway PostgreSQL)
      3. MCP_SHIELD_DB_URL env (custom PostgreSQL)
      4. MCP_SHIELD_DB_PATH env (SQLite file)
      5. Default: mcp_shield_cloud.db (SQLite)
    """
    # If an explicit path is given (tests), use SQLite.
    if db_path is not None:
        from mcp_shield.cloud.db import SqliteStorage
        return SqliteStorage(db_path)

    # Check for Postgres URL.
    pg_url = os.environ.get("DATABASE_URL") or os.environ.get("MCP_SHIELD_DB_URL")
    if pg_url and pg_url.startswith("postgres"):
        from mcp_shield.cloud.storage_postgres import PostgresStorage
        logger.info("using PostgreSQL backend")
        return PostgresStorage(pg_url)

    # Default: SQLite.
    sqlite_path = os.environ.get("MCP_SHIELD_DB_PATH", "mcp_shield_cloud.db")
    from mcp_shield.cloud.db import SqliteStorage
    logger.info("using SQLite backend: %s", sqlite_path)
    return SqliteStorage(sqlite_path)
