# Phase 5 — Cloud Dashboard & Compliance Reports: Detailed Plan

> Spec I implement against. Every endpoint, model, role, and test case is
> concrete. Goal: implement once, green on first run, no conflicts with
> Phase 1-4, no bugs.

## 1. Goal — the commercial tier

Phases 1-4 are a **local proxy**: one agent, one machine, a JSONL audit
log. Phase 5 is the **cloud dashboard**: a web app that aggregates audit
events from many proxy instances across an org, gives admins a single
pane of glass, enforces RBAC, supports SSO, and generates compliance
reports (SOC2, ISO27001, 152-ФЗ).

The proxy (Phase 1-4) is unchanged. It gains ONE new optional flag:
`--cloud-url` + `--cloud-key`. When set, it ships each audit event to the
cloud API as it is written (best-effort; the local JSONL log is still the
source of truth). The cloud is a separate service that ingests, stores,
and presents those events.

## 2. What Phase 5 does NOT do (conflict avoidance)

- Does NOT modify the proxy's security pipeline. Policy, redaction,
  detection, graph, and approval run EXACTLY as in Phase 1-4. The cloud
  is a READ-ONLY consumer of audit events; it never feeds decisions back
  into the proxy in Phase 5 (that's a future "cloud-managed policy" phase).
- Does NOT weaken the tamper-evident log. The local JSONL log is still
  written (Phase 1). The cloud is a SECONDARY copy for aggregation. If the
  cloud is unreachable, the proxy keeps logging locally and retries the
  ship (bounded queue; drops oldest on overflow — never blocks the proxy).
- Does NOT add mandatory dependencies to the core proxy. FastAPI/uvicorn
  are ALREADY in the `[detector]` optional extra. The cloud server uses
  them. The proxy's shipper uses `urllib` (stdlib) — no new core deps.
- Does NOT store secrets. The proxy redacts secrets BEFORE audit (Phase 1),
  so the events shipped to the cloud contain only `[REDACTED:...]` markers.
  The cloud DB never sees a raw secret. Verified in tests.
- Is OPTIONAL. `--cloud-url` unset -> proxy behaves exactly like Phase 1-4.
  The cloud server is a separate process (`mcp-shield-cloud`) that you run
  only if you want the dashboard.

## 3. Architecture

```
   Many proxy instances (Phase 1-4)          Cloud dashboard (Phase 5)
   ┌──────────┐  POST /api/ingest   ┌──────────────────────┐
   │ Proxy A  │ ──────────────────> │  FastAPI server      │
   │ (agent)  │                     │  (mcp-shield-cloud)  │
   └──────────┘                     │                      │
   ┌──────────┐                      │  ┌────────────────┐  │
   │ Proxy B  │ ──────────────>     │  │  SQLite DB     │  │
   │ (agent)  │                     │  │  (events, orgs,│  │
   └──────────┘                     │  │   users, keys) │  │
                                    │  └────────────────┘  │
   Browser (admin)                  │                      │
   ┌──────────┐  GET /dashboard     │  Jinja2 templates     │
   │ Admin UI │ <─────────────────> │  (server-rendered)   │
   └──────────┘                     └──────────────────────┘
```

### 3.1 Two processes

- `mcp-shield` (Phase 1-4): the local proxy. Unchanged except the new
  `--cloud-url`/`--cloud-key` flags + a shipper module.
- `mcp-shield-cloud` (Phase 5): the dashboard server. A FastAPI app that
  ingests events, serves the dashboard UI, and generates reports.

### 3.2 Tech stack (MVP, zero new mandatory deps)

- **FastAPI** — already in `[detector]` optional extra; reuse for the cloud.
- **uvicorn** — ASGI server (already in `[detector]`).
- **sqlite3** — stdlib; file-based DB; zero-config; upgrade to Postgres later.
- **Jinja2** — server-rendered HTML; no React build step for MVP.
- **itsdangerous** — signed session cookies (already a FastAPI/Starlette dep).
- **urllib** — the proxy shipper (stdlib).

The cloud server is installed via `pip install mcp-shield[cloud]` which
adds `fastapi`, `uvicorn`, `jinja2`, `python-multipart` (for forms).

## 4. Data model (cloud/db.py)

SQLite schema (created on first run via `init_db`):

```sql
-- An org (tenant). One per customer.
CREATE TABLE orgs (
    id TEXT PRIMARY KEY,          -- uuid4 hex
    name TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- An API key. A proxy ships events with one. Identifies the org.
CREATE TABLE api_keys (
    key TEXT PRIMARY KEY,          -- random token (e.g. "mcp_live_...")
    org_id TEXT NOT NULL REFERENCES orgs(id),
    label TEXT,                   -- e.g. "prod-proxy-1"
    created_at REAL NOT NULL,
    revoked INTEGER DEFAULT 0
);

-- A user (dashboard login). Belongs to an org. Has a role.
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,           -- pbkdf2_hmac (stdlib); None for SSO-only
    role TEXT NOT NULL,            -- "admin" | "analyst" | "viewer"
    created_at REAL NOT NULL
);

-- An audit event shipped from a proxy. Mirrors the JSONL AuditEntry.
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    seq INTEGER,                  -- the proxy's local seq
    ts TEXT,                      -- ISO timestamp
    decision TEXT,                 -- "allow" | "deny"
    server TEXT,
    tool TEXT,
    args TEXT,                     -- JSON (already redacted)
    reason TEXT,
    rule TEXT,
    redactions TEXT,               -- JSON
    detection TEXT,                -- JSON (Phase 2)
    chain TEXT,                    -- JSON (Phase 3)
    approval TEXT,                 -- JSON (Phase 4)
    received_at REAL NOT NULL      -- server time
);
CREATE INDEX events_org_ts ON events(org_id, ts);
CREATE INDEX events_org_decision ON events(org_id, decision);
```

### 4.1 Python models (cloud/models.py)

```python
@dataclass
class Org:
    id: str
    name: str
    created_at: float

@dataclass
class User:
    id: str
    org_id: str
    email: str
    role: str        # "admin" | "analyst" | "viewer"
    created_at: float

@dataclass
class Event:
    id: int
    org_id: str
    seq: int
    ts: str
    decision: str
    server: str
    tool: str
    args: dict
    reason: str
    rule: str
    redactions: list
    detection: dict | None
    chain: dict | None
    approval: dict | None
    received_at: float
```
