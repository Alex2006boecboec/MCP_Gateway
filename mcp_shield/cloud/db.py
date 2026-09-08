"""SQLite database layer for the cloud dashboard (Phase 5).

Uses stdlib `sqlite3` — zero-config, file-based. Every query is scoped by
org_id (multi-tenant isolation). All queries use parameterized SQL (?)
to prevent SQL injection.

The DB is created on first run via `init_db`. CRUD methods are on the
`Database` class. The class is NOT thread-safe (SQLite with a single
writer); the cloud server is sequential for MVP.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from mcp_shield.cloud.models import ApiKey, Event, Org, User

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    key TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    label TEXT,
    created_at REAL NOT NULL,
    revoked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    role TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    seq INTEGER,
    ts TEXT,
    decision TEXT,
    server TEXT,
    tool TEXT,
    args TEXT,
    reason TEXT,
    rule TEXT,
    redactions TEXT,
    detection TEXT,
    chain TEXT,
    approval TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS events_org_ts ON events(org_id, ts);
CREATE INDEX IF NOT EXISTS events_org_decision ON events(org_id, decision);
"""


class Database:
    """SQLite-backed store for the cloud dashboard."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        # check_same_thread=False allows use across threads (FastAPI runs
        # handlers in a thread pool). A lock serializes writes for safety.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_db()

    def init_db(self) -> None:
        """Create all tables if they don't exist. Idempotent."""
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ----------------------------------------------------------- orgs

    def create_org(self, name: str) -> Org:
        org = Org(id=uuid.uuid4().hex, name=name, created_at=time.time())
        with self._lock:
            self._conn.execute(
                "INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)",
                (org.id, org.name, org.created_at),
            )
            self._conn.commit()
        return org

    def get_org(self, org_id: str) -> Optional[Org]:
        row = self._conn.execute(
            "SELECT id, name, created_at FROM orgs WHERE id = ?", (org_id,)
        ).fetchone()
        if row is None:
            return None
        return Org(id=row["id"], name=row["name"], created_at=row["created_at"])

    # ----------------------------------------------------------- users

    def create_user(self, org_id: str, email: str, password_hash: str, role: str) -> User:
        user = User(
            id=uuid.uuid4().hex, org_id=org_id, email=email, role=role,
            created_at=time.time(), password_hash=password_hash,
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO users (id, org_id, email, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (user.id, user.org_id, user.email, user.password_hash, user.role, user.created_at),
            )
            self._conn.commit()
        return user

    def get_user_by_email(self, email: str) -> Optional[User]:
        row = self._conn.execute(
            "SELECT id, org_id, email, password_hash, role, created_at FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if row is None:
            return None
        return User(
            id=row["id"], org_id=row["org_id"], email=row["email"],
            password_hash=row["password_hash"], role=row["role"],
            created_at=row["created_at"],
        )

    def get_user(self, user_id: str) -> Optional[User]:
        row = self._conn.execute(
            "SELECT id, org_id, email, password_hash, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        return User(
            id=row["id"], org_id=row["org_id"], email=row["email"],
            password_hash=row["password_hash"], role=row["role"],
            created_at=row["created_at"],
        )

    def list_users(self, org_id: str) -> list[User]:
        rows = self._conn.execute(
            "SELECT id, org_id, email, role, created_at FROM users WHERE org_id = ? ORDER BY created_at",
            (org_id,),
        ).fetchall()
        return [
            User(id=r["id"], org_id=r["org_id"], email=r["email"], role=r["role"],
                 created_at=r["created_at"])
            for r in rows
        ]

    # ----------------------------------------------------------- api keys

    def create_api_key(self, org_id: str, label: str) -> ApiKey:
        key = "mcp_live_" + uuid.uuid4().hex
        api_key = ApiKey(key=key, org_id=org_id, label=label, created_at=time.time())
        with self._lock:
            self._conn.execute(
                "INSERT INTO api_keys (key, org_id, label, created_at, revoked) "
                "VALUES (?, ?, ?, ?, 0)",
                (api_key.key, api_key.org_id, api_key.label, api_key.created_at),
            )
            self._conn.commit()
        return api_key

    def validate_api_key(self, key: str) -> Optional[ApiKey]:
        """Return the ApiKey if valid (exists and not revoked), else None."""
        row = self._conn.execute(
            "SELECT key, org_id, label, created_at, revoked FROM api_keys WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None or row["revoked"]:
            return None
        return ApiKey(
            key=row["key"], org_id=row["org_id"], label=row["label"],
            created_at=row["created_at"], revoked=bool(row["revoked"]),
        )

    def revoke_api_key(self, key: str) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE api_keys SET revoked = 1 WHERE key = ?", (key,))
            self._conn.commit()
        return cur.rowcount > 0

    def list_api_keys(self, org_id: str) -> list[ApiKey]:
        rows = self._conn.execute(
            "SELECT key, org_id, label, created_at, revoked FROM api_keys "
            "WHERE org_id = ? ORDER BY created_at",
            (org_id,),
        ).fetchall()
        return [
            ApiKey(key=r["key"], org_id=r["org_id"], label=r["label"],
                   created_at=r["created_at"], revoked=bool(r["revoked"]))
            for r in rows
        ]

    # ----------------------------------------------------------- events

    def insert_event(self, org_id: str, entry: dict[str, Any]) -> bool:
        """Insert an audit event. Idempotent on (org_id, seq): if an event
        with the same seq already exists for this org, it's a no-op (upsert).
        Returns True if inserted, False if duplicate (no-op)."""
        seq = entry.get("seq", 0)
        with self._lock:
            # Check for duplicate.
            existing = self._conn.execute(
                "SELECT 1 FROM events WHERE org_id = ? AND seq = ?", (org_id, seq)
            ).fetchone()
            if existing is not None:
                return False
            self._conn.execute(
                "INSERT INTO events (org_id, seq, ts, decision, server, tool, args, "
                "reason, rule, redactions, detection, chain, approval, received_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    org_id, seq, entry.get("ts", ""), entry.get("decision", ""),
                    entry.get("server", ""), entry.get("tool", ""),
                    json.dumps(entry.get("args", {}), ensure_ascii=False),
                    entry.get("reason", ""), entry.get("rule", ""),
                    json.dumps(entry.get("redactions", []), ensure_ascii=False),
                    json.dumps(entry.get("detection"), ensure_ascii=False) if entry.get("detection") else None,
                    json.dumps(entry.get("chain"), ensure_ascii=False) if entry.get("chain") else None,
                    json.dumps(entry.get("approval"), ensure_ascii=False) if entry.get("approval") else None,
                    time.time(),
                ),
            )
            self._conn.commit()
        return True

    def query_events(
        self,
        org_id: str,
        *,
        decision: Optional[str] = None,
        server: Optional[str] = None,
        tool: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Event]:
        """Query events for an org with optional filters. Always scoped by org_id."""
        sql = "SELECT * FROM events WHERE org_id = ?"
        params: list[Any] = [org_id]
        if decision:
            sql += " AND decision = ?"
            params.append(decision)
        if server:
            sql += " AND server = ?"
            params.append(server)
        if tool:
            sql += " AND tool = ?"
            params.append(tool)
        if start:
            sql += " AND ts >= ?"
            params.append(start)
        if end:
            sql += " AND ts <= ?"
            params.append(end)
        sql += " ORDER BY received_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]

    def count_events(self, org_id: str, *, decision: Optional[str] = None) -> int:
        sql = "SELECT COUNT(*) as c FROM events WHERE org_id = ?"
        params: list[Any] = [org_id]
        if decision:
            sql += " AND decision = ?"
            params.append(decision)
        row = self._conn.execute(sql, params).fetchone()
        return row["c"] if row else 0

    def get_event(self, org_id: str, event_id: int) -> Optional[Event]:
        row = self._conn.execute(
            "SELECT * FROM events WHERE org_id = ? AND id = ?", (org_id, event_id)
        ).fetchone()
        if row is None:
            return None
        return _row_to_event(row)

    def summary(self, org_id: str, *, start: Optional[str] = None, end: Optional[str] = None) -> dict[str, int]:
        """Return summary counts for the dashboard cards."""
        sql = "SELECT decision, COUNT(*) as c FROM events WHERE org_id = ?"
        params: list[Any] = [org_id]
        if start:
            sql += " AND ts >= ?"
            params.append(start)
        if end:
            sql += " AND ts <= ?"
            params.append(end)
        sql += " GROUP BY decision"
        rows = self._conn.execute(sql, params).fetchall()
        counts = {"allow": 0, "deny": 0}
        for r in rows:
            counts[r["decision"]] = r["c"]
        counts["total"] = counts["allow"] + counts["deny"]
        return counts


def _row_to_event(row: sqlite3.Row) -> Event:
    return Event(
        id=row["id"], org_id=row["org_id"], seq=row["seq"] or 0, ts=row["ts"] or "",
        decision=row["decision"] or "", server=row["server"] or "",
        tool=row["tool"] or "", args=json.loads(row["args"] or "{}"),
        reason=row["reason"] or "", rule=row["rule"] or "",
        redactions=json.loads(row["redactions"] or "[]"),
        detection=json.loads(row["detection"]) if row["detection"] else None,
        chain=json.loads(row["chain"]) if row["chain"] else None,
        approval=json.loads(row["approval"]) if row["approval"] else None,
        received_at=row["received_at"],
    )
