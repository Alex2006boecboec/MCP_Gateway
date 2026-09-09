"""Simple migration runner for PostgreSQL.

Applies SQL files from migrations/ in order. Tracks applied
migrations in the `schema_migrations` table. Idempotent: re-running
is a no-op if all migrations are already applied.

Not using Alembic to avoid adding a dependency. The migrator is
intentionally minimal: read .sql files, execute them, record.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("mcp_shield.cloud.migrator")

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def run_migrations(conn) -> list[int]:
    """Apply all pending migrations. `conn` is a psycopg2 connection.

    Returns list of migration IDs that were applied (empty if none).
    """
    # Ensure schema_migrations table exists.
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at DOUBLE PRECISION NOT NULL
                )
            """)
            cur.execute("SELECT id FROM schema_migrations ORDER BY id")
            applied = {row[0] for row in cur.fetchall()}

    # Find all .sql files, sorted by numeric prefix.
    sql_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    newly_applied: list[int] = []
    for sql_file in sql_files:
        # Extract migration ID from filename (e.g. "001_initial.sql" -> 1).
        try:
            mig_id = int(sql_file.stem.split("_")[0])
        except (ValueError, IndexError):
            logger.warning("skipping migration file with bad name: %s", sql_file)
            continue
        if mig_id in applied:
            continue
        sql = sql_file.read_text(encoding="utf-8")
        logger.info("applying migration %d: %s", mig_id, sql_file.name)
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migrations (id, name, applied_at) VALUES (%s, %s, %s)",
                    (mig_id, sql_file.name, time.time()),
                )
        newly_applied.append(mig_id)
    if newly_applied:
        logger.info("applied %d migrations: %s", len(newly_applied), newly_applied)
    else:
        logger.info("no pending migrations")
    return newly_applied
