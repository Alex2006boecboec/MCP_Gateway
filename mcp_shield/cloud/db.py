"""SQLite storage backend for the cloud dashboard.

Uses stdlib `sqlite3` — zero-config, file-based. Every query is scoped by
org_id (multi-tenant isolation). All queries use parameterized SQL (?)
to prevent SQL injection.

This is the SQLite backend (for tests and local dev). For production,
see storage_postgres.py. Both implement the Storage protocol from
storage.py.

Thread-safety: check_same_thread=False + a lock serializes writes.
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
    revoked INTEGER DEFAULT 0,
    scopes TEXT DEFAULT '["ingest"]',
    allowed_ips TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    role TEXT NOT NULL,
    created_at REAL NOT NULL,
    token_version INTEGER DEFAULT 0,
    must_change_password INTEGER DEFAULT 0,
    deleted INTEGER DEFAULT 0
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
CREATE TABLE IF NOT EXISTS password_resets (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    expires_at REAL NOT NULL,
    used INTEGER DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS dashboard_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    actor_id TEXT NOT NULL REFERENCES users(id),
    actor_email TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS dashboard_actions_org ON dashboard_actions(org_id, created_at);
"""


def _ensure_columns(conn: sqlite3.Connection) -> None:
    """Add columns that may be missing in older DBs (ALTER TABLE)."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "token_version" not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0")
    if "must_change_password" not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0")
    if "deleted" not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN deleted INTEGER DEFAULT 0")
    existing_keys = {row[1] for row in conn.execute("PRAGMA table_info(api_keys)").fetchall()}
    if "scopes" not in existing_keys:
        conn.execute("ALTER TABLE api_keys ADD COLUMN scopes TEXT DEFAULT '[\"ingest\"]'")
    if "allowed_ips" not in existing_keys:
        conn.execute("ALTER TABLE api_keys ADD COLUMN allowed_ips TEXT DEFAULT '[]'")
    conn.commit()


class SqliteStorage:
    """SQLite-backed store for the cloud dashboard. Implements Storage."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_db()

    def init_db(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            _ensure_columns(self._conn)
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
            "SELECT id, org_id, email, password_hash, role, created_at, token_version, "
            "must_change_password, deleted FROM users WHERE email = ? AND deleted = 0",
            (email,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_user(row)

    def get_user(self, user_id: str) -> Optional[User]:
        row = self._conn.execute(
            "SELECT id, org_id, email, password_hash, role, created_at, token_version, "
            "must_change_password, deleted FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_user(row)

    def list_users(self, org_id: str) -> list[User]:
        rows = self._conn.execute(
            "SELECT id, org_id, email, password_hash, role, created_at, token_version, "
            "must_change_password, deleted FROM users WHERE org_id = ? AND deleted = 0 "
            "ORDER BY created_at",
            (org_id,),
        ).fetchall()
        return [_row_to_user(r) for r in rows]

    def update_password(self, user_id: str, new_hash: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 0, "
                "token_version = token_version + 1 WHERE id = ?",
                (new_hash, user_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def delete_user(self, user_id: str) -> bool:
        """Soft delete: set deleted=1 and invalidate sessions."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET deleted = 1, token_version = token_version + 1 WHERE id = ?",
                (user_id,),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def update_user_role(self, user_id: str, role: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET role = ? WHERE id = ?",
                (role, user_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def count_admins(self, org_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) as c FROM users WHERE org_id = ? AND role = 'admin' AND deleted = 0",
            (org_id,),
        ).fetchone()
        return row["c"] if row else 0

    # ----------------------------------------------------------- api keys

    def create_api_key(self, org_id: str, label: str, scopes: list[str] | None = None,
                       allowed_ips: list[str] | None = None) -> ApiKey:
        key = "mcp_live_" + uuid.uuid4().hex
        scopes = scopes or ["ingest"]
        allowed_ips = allowed_ips or []
        api_key = ApiKey(key=key, org_id=org_id, label=label, created_at=time.time(),
                        scopes=scopes, allowed_ips=allowed_ips)
        with self._lock:
            self._conn.execute(
                "INSERT INTO api_keys (key, org_id, label, created_at, revoked, scopes, allowed_ips) "
                "VALUES (?, ?, ?, ?, 0, ?, ?)",
                (api_key.key, api_key.org_id, api_key.label, api_key.created_at,
                 json.dumps(scopes), json.dumps(allowed_ips)),
            )
            self._conn.commit()
        return api_key

    def validate_api_key(self, key: str) -> Optional[ApiKey]:
        row = self._conn.execute(
            "SELECT key, org_id, label, created_at, revoked, scopes, allowed_ips FROM api_keys WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None or row["revoked"]:
            return None
        return ApiKey(
            key=row["key"], org_id=row["org_id"], label=row["label"],
            created_at=row["created_at"], revoked=bool(row["revoked"]),
            scopes=json.loads(row["scopes"] or '["ingest"]'),
            allowed_ips=json.loads(row["allowed_ips"] or "[]"),
        )

    def revoke_api_key(self, key: str) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE api_keys SET revoked = 1 WHERE key = ?", (key,))
            self._conn.commit()
        return cur.rowcount > 0

    def list_api_keys(self, org_id: str) -> list[ApiKey]:
        rows = self._conn.execute(
            "SELECT key, org_id, label, created_at, revoked, scopes, allowed_ips FROM api_keys "
            "WHERE org_id = ? ORDER BY created_at",
            (org_id,),
        ).fetchall()
        return [
            ApiKey(key=r["key"], org_id=r["org_id"], label=r["label"],
                   created_at=r["created_at"], revoked=bool(r["revoked"]),
                   scopes=json.loads(r["scopes"] or '["ingest"]'),
                   allowed_ips=json.loads(r["allowed_ips"] or "[]"))
            for r in rows
        ]

    # ----------------------------------------------------------- events

    def insert_event(self, org_id: str, entry: dict[str, Any]) -> bool:
        seq = entry.get("seq", 0)
        with self._lock:
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

    def delete_old_events(self, days: int) -> int:
        """Delete events older than N days. Returns count deleted."""
        cutoff = time.time() - (days * 86400)
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM events WHERE received_at < ?", (cutoff,)
            )
            self._conn.commit()
        return cur.rowcount

    # ----------------------------------------------------------- password resets

    def create_password_reset(self, user_id: str, ttl: float = 3600) -> str:
        """Create a password reset token. Returns the token string."""
        token = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO password_resets (token, user_id, expires_at, used, created_at) "
                "VALUES (?, ?, ?, 0, ?)",
                (token, user_id, now + ttl, now),
            )
            self._conn.commit()
        return token

    def get_password_reset(self, token: str) -> Optional[dict]:
        """Get a password reset token if valid (not used, not expired)."""
        row = self._conn.execute(
            "SELECT token, user_id, expires_at, used FROM password_resets WHERE token = ?",
            (token,),
        ).fetchone()
        if row is None:
            return None
        if row["used"]:
            return None
        if time.time() > row["expires_at"]:
            return None
        return {"token": row["token"], "user_id": row["user_id"]}

    def use_password_reset(self, token: str) -> bool:
        """Mark a password reset token as used."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE password_resets SET used = 1 WHERE token = ?", (token,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def cleanup_password_resets(self) -> int:
        """Delete expired/used password reset tokens."""
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM password_resets WHERE expires_at < ? OR used = 1", (now,)
            )
            self._conn.commit()
        return cur.rowcount

    # ----------------------------------------------------------- dashboard audit

    def log_action(self, org_id: str, actor_id: str, actor_email: str,
                   action: str, target_type: str = "", target_id: str = "",
                   detail: str = "") -> None:
        """Record a dashboard action for audit."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO dashboard_actions (org_id, actor_id, actor_email, action, "
                "target_type, target_id, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (org_id, actor_id, actor_email, action, target_type, target_id, detail, time.time()),
            )
            self._conn.commit()

    def query_actions(self, org_id: str, limit: int = 100, offset: int = 0) -> list[dict]:
        """Query dashboard actions for an org."""
        rows = self._conn.execute(
            "SELECT id, org_id, actor_id, actor_email, action, target_type, target_id, detail, created_at "
            "FROM dashboard_actions WHERE org_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (org_id, limit, offset),
        ).fetchall()
        return [
            {
                "id": r["id"], "org_id": r["org_id"], "actor_id": r["actor_id"],
                "actor_email": r["actor_email"], "action": r["action"],
                "target_type": r["target_type"], "target_id": r["target_id"],
                "detail": r["detail"], "created_at": r["created_at"],
            }
            for r in rows
        ]


# Backward-compat alias (existing tests import Database).
Database = SqliteStorage


# ----------------------------------------------------------- helpers


def _row_to_user(row: sqlite3.Row) -> User:
    return User(
        id=row["id"], org_id=row["org_id"], email=row["email"],
        password_hash=row["password_hash"], role=row["role"],
        created_at=row["created_at"],
        token_version=row["token_version"] if "token_version" in row.keys() else 0,
        must_change_password=bool(row["must_change_password"]) if "must_change_password" in row.keys() else False,
        deleted=bool(row["deleted"]) if "deleted" in row.keys() else False,
    )


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
