"""PostgreSQL storage backend for the cloud dashboard (production).

Uses psycopg2 with a ThreadedConnectionPool. Every query is org-scoped
(multi-tenant isolation). All queries use parameterized SQL (%s) to
prevent SQL injection. JSONB columns for args/redactions/detection/chain.

This backend is used when DATABASE_URL env is set (e.g. on Railway).
For tests/local dev, see db.py (SqliteStorage).
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Optional

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

from mcp_shield.cloud.models import ApiKey, Event, Org, User

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    key TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    label TEXT,
    created_at DOUBLE PRECISION NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    scopes JSONB DEFAULT '["ingest"]'::jsonb,
    allowed_ips JSONB DEFAULT '[]'::jsonb
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    role TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    token_version INTEGER DEFAULT 0,
    must_change_password BOOLEAN DEFAULT FALSE,
    deleted BOOLEAN DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    seq INTEGER,
    ts TEXT,
    decision TEXT,
    server TEXT,
    tool TEXT,
    args JSONB,
    reason TEXT,
    rule TEXT,
    redactions JSONB,
    detection JSONB,
    chain JSONB,
    approval JSONB,
    received_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS events_org_ts ON events(org_id, ts);
CREATE INDEX IF NOT EXISTS events_org_decision ON events(org_id, decision);
CREATE UNIQUE INDEX IF NOT EXISTS events_org_seq_unique ON events(org_id, seq) WHERE seq IS NOT NULL;
CREATE TABLE IF NOT EXISTS password_resets (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    expires_at DOUBLE PRECISION NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS dashboard_actions (
    id SERIAL PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    actor_id TEXT NOT NULL REFERENCES users(id),
    actor_email TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    created_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS dashboard_actions_org ON dashboard_actions(org_id, created_at);
"""


class PostgresStorage:
    """PostgreSQL-backed store. Implements the Storage protocol."""

    def __init__(self, url: str, min_conn: int = 1, max_conn: int = 10):
        self._pool = ThreadedConnectionPool(min_conn, max_conn, url)
        self.init_db()

    def _conn(self):
        return self._pool.getconn()

    def _put(self, conn):
        self._pool.putconn(conn)

    def init_db(self) -> None:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(SCHEMA_SQL)
        finally:
            self._put(conn)

    def close(self) -> None:
        self._pool.closeall()

    # ----------------------------------------------------------- orgs

    def create_org(self, name: str) -> Org:
        org = Org(id=uuid.uuid4().hex, name=name, created_at=time.time())
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO orgs (id, name, created_at) VALUES (%s, %s, %s)",
                        (org.id, org.name, org.created_at),
                    )
        finally:
            self._put(conn)
        return org

    def get_org(self, org_id: str) -> Optional[Org]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id, name, created_at FROM orgs WHERE id = %s", (org_id,))
                row = cur.fetchone()
            if row is None:
                return None
            return Org(id=row[0], name=row[1], created_at=row[2])
        finally:
            self._put(conn)

    # ----------------------------------------------------------- users

    def create_user(self, org_id: str, email: str, password_hash: str, role: str) -> User:
        user = User(
            id=uuid.uuid4().hex, org_id=org_id, email=email, role=role,
            created_at=time.time(), password_hash=password_hash,
        )
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO users (id, org_id, email, password_hash, role, created_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (user.id, user.org_id, user.email, user.password_hash, user.role, user.created_at),
                    )
        finally:
            self._put(conn)
        return user

    def get_user_by_email(self, email: str) -> Optional[User]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, org_id, email, password_hash, role, created_at, token_version, "
                    "must_change_password, deleted FROM users WHERE email = %s AND deleted = FALSE",
                    (email,),
                )
                row = cur.fetchone()
            if row is None:
                return None
            return _pg_row_to_user(row)
        finally:
            self._put(conn)

    def get_user(self, user_id: str) -> Optional[User]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, org_id, email, password_hash, role, created_at, token_version, "
                    "must_change_password, deleted FROM users WHERE id = %s",
                    (user_id,),
                )
                row = cur.fetchone()
            if row is None:
                return None
            return _pg_row_to_user(row)
        finally:
            self._put(conn)

    def list_users(self, org_id: str) -> list[User]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, org_id, email, password_hash, role, created_at, token_version, "
                    "must_change_password, deleted FROM users WHERE org_id = %s AND deleted = FALSE "
                    "ORDER BY created_at",
                    (org_id,),
                )
                rows = cur.fetchall()
            return [_pg_row_to_user(r) for r in rows]
        finally:
            self._put(conn)

    def update_password(self, user_id: str, new_hash: str) -> bool:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET password_hash = %s, must_change_password = FALSE, "
                        "token_version = token_version + 1 WHERE id = %s",
                        (new_hash, user_id),
                    )
                    return cur.rowcount > 0
        finally:
            self._put(conn)

    def delete_user(self, user_id: str) -> bool:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET deleted = TRUE, token_version = token_version + 1 WHERE id = %s",
                        (user_id,),
                    )
                    return cur.rowcount > 0
        finally:
            self._put(conn)

    def update_user_role(self, user_id: str, role: str) -> bool:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
                    return cur.rowcount > 0
        finally:
            self._put(conn)

    def count_admins(self, org_id: str) -> int:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM users WHERE org_id = %s AND role = 'admin' AND deleted = FALSE",
                    (org_id,),
                )
                row = cur.fetchone()
            return row[0] if row else 0
        finally:
            self._put(conn)

    # ----------------------------------------------------------- api keys

    def create_api_key(self, org_id: str, label: str, scopes: list[str] | None = None,
                       allowed_ips: list[str] | None = None) -> ApiKey:
        key = "mcp_live_" + uuid.uuid4().hex
        scopes = scopes or ["ingest"]
        allowed_ips = allowed_ips or []
        api_key = ApiKey(key=key, org_id=org_id, label=label, created_at=time.time(),
                        scopes=scopes, allowed_ips=allowed_ips)
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO api_keys (key, org_id, label, created_at, revoked, scopes, allowed_ips) "
                        "VALUES (%s, %s, %s, %s, FALSE, %s::jsonb, %s::jsonb)",
                        (api_key.key, api_key.org_id, api_key.label, api_key.created_at,
                         json.dumps(scopes), json.dumps(allowed_ips)),
                    )
        finally:
            self._put(conn)
        return api_key

    def validate_api_key(self, key: str) -> Optional[ApiKey]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT key, org_id, label, created_at, revoked, scopes, allowed_ips FROM api_keys WHERE key = %s",
                    (key,),
                )
                row = cur.fetchone()
            if row is None or row[4]:  # revoked
                return None
            return ApiKey(
                key=row[0], org_id=row[1], label=row[2], created_at=row[3],
                revoked=bool(row[4]), scopes=row[5] if row[5] else ["ingest"],
                allowed_ips=row[6] if row[6] else [],
            )
        finally:
            self._put(conn)

    def revoke_api_key(self, key: str) -> bool:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE api_keys SET revoked = TRUE WHERE key = %s", (key,))
                    return cur.rowcount > 0
        finally:
            self._put(conn)

    def list_api_keys(self, org_id: str) -> list[ApiKey]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT key, org_id, label, created_at, revoked, scopes, allowed_ips FROM api_keys "
                    "WHERE org_id = %s ORDER BY created_at",
                    (org_id,),
                )
                rows = cur.fetchall()
            return [
                ApiKey(key=r[0], org_id=r[1], label=r[2], created_at=r[3],
                       revoked=bool(r[4]), scopes=r[5] if r[5] else ["ingest"],
                       allowed_ips=r[6] if r[6] else [])
                for r in rows
            ]
        finally:
            self._put(conn)

    # ----------------------------------------------------------- events

    def insert_event(self, org_id: str, entry: dict[str, Any]) -> bool:
        seq = entry.get("seq", 0)
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO events (org_id, seq, ts, decision, server, tool, args, "
                        "reason, rule, redactions, detection, chain, approval, received_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, "
                        "%s::jsonb, %s::jsonb, %s::jsonb, %s) "
                        "ON CONFLICT (org_id, seq) WHERE seq IS NOT NULL DO NOTHING",
                        (
                            org_id, seq, entry.get("ts", ""), entry.get("decision", ""),
                            entry.get("server", ""), entry.get("tool", ""),
                            json.dumps(entry.get("args", {}), ensure_ascii=False),
                            entry.get("reason", ""), entry.get("rule", ""),
                            json.dumps(entry.get("redactions", []), ensure_ascii=False),
                            json.dumps(entry.get("detection")) if entry.get("detection") else None,
                            json.dumps(entry.get("chain")) if entry.get("chain") else None,
                            json.dumps(entry.get("approval")) if entry.get("approval") else None,
                            time.time(),
                        ),
                    )
                    return cur.rowcount > 0
        except psycopg2.IntegrityError:
            return False  # duplicate (org_id, seq)
        finally:
            self._put(conn)

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
        sql = "SELECT id, org_id, seq, ts, decision, server, tool, args, reason, rule, redactions, detection, chain, approval, received_at FROM events WHERE org_id = %s"
        params: list[Any] = [org_id]
        if decision:
            sql += " AND decision = %s"
            params.append(decision)
        if server:
            sql += " AND server = %s"
            params.append(server)
        if tool:
            sql += " AND tool = %s"
            params.append(tool)
        if start:
            sql += " AND ts >= %s"
            params.append(start)
        if end:
            sql += " AND ts <= %s"
            params.append(end)
        sql += " ORDER BY received_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
            return [_pg_row_to_event(r) for r in rows]
        finally:
            self._put(conn)

    def count_events(self, org_id: str, *, decision: Optional[str] = None) -> int:
        sql = "SELECT COUNT(*) FROM events WHERE org_id = %s"
        params: list[Any] = [org_id]
        if decision:
            sql += " AND decision = %s"
            params.append(decision)
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                row = cur.fetchone()
            return row[0] if row else 0
        finally:
            self._put(conn)

    def get_event(self, org_id: str, event_id: int) -> Optional[Event]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, org_id, seq, ts, decision, server, tool, args, reason, rule, "
                    "redactions, detection, chain, approval, received_at "
                    "FROM events WHERE org_id = %s AND id = %s",
                    (org_id, event_id),
                )
                row = cur.fetchone()
            if row is None:
                return None
            return _pg_row_to_event(row)
        finally:
            self._put(conn)

    def summary(self, org_id: str, *, start: Optional[str] = None, end: Optional[str] = None) -> dict[str, int]:
        sql = "SELECT decision, COUNT(*) FROM events WHERE org_id = %s"
        params: list[Any] = [org_id]
        if start:
            sql += " AND ts >= %s"
            params.append(start)
        if end:
            sql += " AND ts <= %s"
            params.append(end)
        sql += " GROUP BY decision"
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
            counts = {"allow": 0, "deny": 0}
            for r in rows:
                counts[r[0]] = r[1]
            counts["total"] = counts["allow"] + counts["deny"]
            return counts
        finally:
            self._put(conn)

    def delete_old_events(self, days: int) -> int:
        cutoff = time.time() - (days * 86400)
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM events WHERE received_at < %s", (cutoff,))
                    return cur.rowcount
        finally:
            self._put(conn)

    # ----------------------------------------------------------- password resets

    def create_password_reset(self, user_id: str, ttl: float = 3600) -> str:
        token = uuid.uuid4().hex
        now = time.time()
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO password_resets (token, user_id, expires_at, used, created_at) "
                        "VALUES (%s, %s, %s, FALSE, %s)",
                        (token, user_id, now + ttl, now),
                    )
            return token
        finally:
            self._put(conn)

    def get_password_reset(self, token: str) -> Optional[dict]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT token, user_id FROM password_resets "
                    "WHERE token = %s AND used = FALSE AND expires_at > %s",
                    (token, time.time()),
                )
                row = cur.fetchone()
            if row is None:
                return None
            return {"token": row[0], "user_id": row[1]}
        finally:
            self._put(conn)

    def use_password_reset(self, token: str) -> bool:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE password_resets SET used = TRUE WHERE token = %s", (token,))
                    return cur.rowcount > 0
        finally:
            self._put(conn)

    def cleanup_password_resets(self) -> int:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM password_resets WHERE expires_at < %s OR used = TRUE",
                        (time.time(),),
                    )
                    return cur.rowcount
        finally:
            self._put(conn)

    # ----------------------------------------------------------- dashboard audit

    def log_action(self, org_id: str, actor_id: str, actor_email: str,
                   action: str, target_type: str = "", target_id: str = "",
                   detail: str = "") -> None:
        conn = self._conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO dashboard_actions (org_id, actor_id, actor_email, action, "
                        "target_type, target_id, detail, created_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (org_id, actor_id, actor_email, action, target_type, target_id, detail, time.time()),
                    )
        finally:
            self._put(conn)

    def query_actions(self, org_id: str, limit: int = 100, offset: int = 0) -> list[dict]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, org_id, actor_id, actor_email, action, target_type, target_id, detail, created_at "
                    "FROM dashboard_actions WHERE org_id = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (org_id, limit, offset),
                )
                rows = cur.fetchall()
            return [
                {
                    "id": r[0], "org_id": r[1], "actor_id": r[2], "actor_email": r[3],
                    "action": r[4], "target_type": r[5], "target_id": r[6],
                    "detail": r[7], "created_at": r[8],
                }
                for r in rows
            ]
        finally:
            self._put(conn)


# ----------------------------------------------------------- helpers


def _pg_row_to_user(row) -> User:
    return User(
        id=row[0], org_id=row[1], email=row[2], password_hash=row[3],
        role=row[4], created_at=row[5], token_version=row[6],
        must_change_password=bool(row[7]), deleted=bool(row[8]),
    )


def _pg_row_to_event(row) -> Event:
    return Event(
        id=row[0], org_id=row[1], seq=row[2] or 0, ts=row[3] or "",
        decision=row[4] or "", server=row[5] or "", tool=row[6] or "",
        args=row[7] if row[7] else {}, reason=row[8] or "", rule=row[9] or "",
        redactions=row[10] if row[10] else [],
        detection=row[11], chain=row[12], approval=row[13],
        received_at=row[14],
    )
