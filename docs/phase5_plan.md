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

## 5. RBAC (cloud/rbac.py)

Three roles, per-org:

| Role | View events | Manage users | Manage API keys | View reports | Manage org |
|---|---|---|---|---|---|
| admin | yes | yes | yes | yes | yes |
| analyst | yes | no | no | yes | no |
| viewer | yes | no | no | no | no |

```python
def can(role: str, action: str) -> bool:
    """Return True if `role` may perform `action`.
    actions: view_events, manage_users, manage_keys, view_reports, manage_org"""
```

Enforced in every route via a dependency that reads the session user and
checks `can(user.role, action)`. A viewer hitting a manage route gets 403.

## 6. Authentication (cloud/auth.py)

Two mechanisms, both optional:

### 6.1 Password (MVP, always available)

- `POST /login` with email + password -> signed session cookie.
- Passwords hashed with `hashlib.pbkdf2_hmac` (stdlib, no bcrypt dep).
- Session cookie signed with `itsdangerous` (a Starlette dep already).
- Logout clears the cookie.

### 6.2 SSO / OIDC (optional, configured via env)

- `MCP_SHIELD_OIDC_CLIENT_ID` / `MCP_SHIELD_OIDC_CLIENT_SECRET` /
  `MCP_SHIELD_OIDC_DISCOVERY_URL` env vars.
- `GET /sso/login` -> redirect to IdP -> callback -> create/find user -> session.
- If OIDC env vars are unset, the SSO endpoints return 501 (not configured).
- Uses `urllib` for the token exchange (no `authlib` dep for MVP).

### 6.3 API key (for the proxy shipper, NOT for dashboard users)

- The proxy ships events with `Authorization: Bearer mcp_live_...`.
- The ingest endpoint validates the key, resolves the org, stores the event.
- API keys are NOT user logins; they're machine credentials.

```python
def hash_password(password: str) -> str: ...
def verify_password(password: str, stored_hash: str) -> bool: ...
def create_session(user: User) -> str: ...   # signed cookie
def verify_session(cookie: str) -> User | None: ...
```

## 7. The ingest API (cloud/api_ingest.py)

```python
POST /api/ingest
Headers: Authorization: Bearer <api_key>
Body: { "entries": [ <AuditEntry dict>, ... ] }
Response: 200 { "accepted": N } | 401 | 429
```

- Validates the API key -> resolves org_id.
- Each entry is the JSON of a Phase 1-4 AuditEntry (with detection/chain/
  approval fields if present).
- Idempotent on (org_id, seq): a re-ship of the same seq is a no-op
  (upsert). This makes retries safe.
- Rate-limited per key (simple in-memory token bucket; 100 req/min default).
- Never stores secrets (args are already redacted by the proxy).
- Returns 200 with the count accepted; 401 on bad key; 429 on rate limit.

## 8. The dashboard UI (cloud/dashboard.py)

Server-rendered HTML (Jinja2). No React, no build step. Minimal vanilla JS
for table sorting and a date-range picker.

### 8.1 Routes (all require a logged-in user)

| Route | Role | What |
|---|---|---|
| GET / | any | redirect to /dashboard |
| GET /login | any | login form |
| POST /login | any | password login |
| GET /logout | any | clear session |
| GET /dashboard | viewer+ | event list (paginated, filterable) |
| GET /events/{id} | viewer+ | single event detail (args, detection, chain, approval) |
| GET /reports | analyst+ | compliance reports page (generate + download) |
| GET /reports/soc2 | analyst+ | SOC2 summary (HTML + CSV download) |
| GET /reports/iso27001 | analyst+ | ISO27001 summary |
| GET /reports/152fz | analyst+ | 152-ФЗ summary (Russian compliance) |
| GET /users | admin | user list for this org |
| POST /users | admin | create user |
| GET /keys | admin | API key list for this org |
| POST /keys | admin | create API key |

### 8.2 Dashboard page

- Table: time, decision (allow/deny badge), server, tool, reason, rule.
- Filters: decision (all/allow/deny), server, tool, date range, search box.
- Pagination: 50 per page.
- Click a row -> event detail (full args, detection signals, chain, approval).
- Summary cards at top: total calls, blocks, injections detected, chains
  blocked, approvals (approve/deny/timeout) — for the selected date range.

## 9. Compliance reports (cloud/reports.py)

Generate summaries over a date range for a given framework. Output as
HTML (view in browser) and CSV (download).

### 9.1 SOC2 (security)

- Total tool calls, allow/deny counts.
- Injection attempts detected + blocked.
- Cross-server chains detected + blocked.
- Approval outcomes (approve/deny/timeout).
- Top blocked tools (by count).
- Top blocked servers.
- Policy violations by rule.
- Audit log integrity (if the proxy ships hash-chain data, verify it).

### 9.2 ISO27001 (information security)

- Same event data, grouped by ISO27001 Annex A control:
  - A.8.1 (access control): blocks on unauthorized tools.
  - A.8.2 (information classification): secret redactions count.
  - A.12.6 (technical vulnerabilities): injection attempts.
  - A.13.1 (network security): SSRF blocks, external sends.
- Maps each block/detection to a control and counts.

### 9.3 152-ФЗ (Russian personal data law)

- Counts of events involving potential PII exfiltration (chains with
  read:database or read:env to network:send).
- Summary of approvals (who approved what, when).
- Event log export (CSV) for the reporting period.

```python
def generate_report(org_id: str, framework: str, start: str, end: str) -> dict:
    """Return a dict with: title, period, summary_cards, rows, controls.
    The dashboard renders it as HTML; /download renders it as CSV."""
```

## 10. The proxy shipper (cloud/shipper.py) - in the PROXY, not the cloud

This module lives in `mcp_shield/` (the proxy package) and ships audit
events to the cloud. It is called by the AuditLogger after each write.

```python
class CloudShipper:
    def __init__(self, url: str, key: str, max_queue: int = 1000):
        self.url = url
        self.key = key
        self._queue: list[dict] = []
        self._max_queue = max_queue

    def ship(self, entry: dict) -> None:
        """Add an entry to the queue. Best-effort, never raises.
        If the queue is full, drop the OLDEST (keep recent). Never blocks."""
        self._queue.append(entry)
        if len(self._queue) > self._max_queue:
            self._queue.pop(0)

    def flush(self) -> int:
        """POST all queued entries to the cloud. Returns count shipped.
        On failure, keeps them in the queue for the next flush. Never raises."""
```

The AuditLogger calls `shipper.ship(entry)` after each `_append`. A
background timer (or the next audit call) triggers `flush()`. For MVP,
flush is synchronous on a timer thread (every 5s) — simple, no async.

### 10.1 Integration into audit.py

```python
class AuditLogger:
    def __init__(self, path, shipper=None):
        self.shipper = shipper
        ...

    def log(self, ...) -> AuditEntry:
        entry = ...
        self._append(entry)
        if self.shipper is not None:
            try: self.shipper.ship(asdict(entry))
            except Exception: pass  # never block on the shipper
        return entry
```

### 10.2 Integration into cli.py

New flags:
- `--cloud-url URL`: the cloud ingest endpoint. Enables the shipper.
- `--cloud-key KEY`: the API key for the org.

## 11. Edge cases & bug-prevention (the critical list)

1. **Cloud unreachable**
   -> The shipper keeps entries in its bounded queue. The proxy keeps
   logging locally (JSONL). On reconnect, the queue flushes. Never blocks
   the proxy. Queue overflow drops OLDEST (recent events are more valuable).

2. **Secrets in shipped events**
   -> The proxy redacts BEFORE audit (Phase 1). The shipper ships the
   AuditEntry which has redacted args. The cloud never sees a raw secret.
   Verified in tests: a secret in original args is [REDACTED:...] in the
   shipped event AND in the cloud DB.

3. **Duplicate events (re-ship on retry)**
   -> The ingest endpoint is idempotent on (org_id, seq). A re-ship of the
   same seq is a no-op (upsert). Retries are safe.

4. **Multi-tenant data leak**
   -> Every query is scoped by org_id (from the session user or the API key).
   A user in org A can NEVER see org B's events. Enforced in the DB layer
   (every SELECT has WHERE org_id = ?) AND in the API (the org_id comes
   from the authenticated session/key, never from the request body).

5. **RBAC bypass**
   -> Every route checks `can(user.role, action)`. A viewer hitting
   /users or /keys gets 403. Tested: a viewer POST to /users returns 403.

6. **SQL injection**
   -> All queries use parameterized SQL (?). No string interpolation into
   SQL. The `server`/`tool` filter values are passed as params, never
   concatenated.

7. **Session forgery**
   -> Session cookies are signed with itsdangerous. A tampered cookie is
   rejected (verify_session returns None -> redirect to /login).

8. **Password storage**
   -> pbkdf2_hmac (stdlib) with a per-user salt. No plaintext passwords
   stored. No bcrypt dep (keep it stdlib for MVP).

9. **API key revocation**
   -> Revoked keys (revoked=1) are rejected at ingest. The proxy gets 401
   and keeps logging locally (its queue retries, but if the key is revoked,
   it will keep failing - documented; the admin should update the proxy's
   --cloud-key or disable --cloud-url).

10. **Large event batches**
    -> The ingest endpoint caps a batch at 100 entries per request. Larger
    batches get 413. The proxy ships in batches of <= 50.

11. **DB concurrency**
    -> SQLite with a single writer (the cloud server is sequential for MVP).
    Document: for high throughput, upgrade to Postgres. SQLite is fine for
    MVP (100s of events/sec).

12. **Cloud server crash**
    -> The SQLite DB is on disk. Restart the server -> it resumes. Events
    already ingested are in the DB. The proxy's queue retries unsent events.

13. **No users / no org on first run**
    -> `mcp-shield-cloud init` creates a default org + admin user (prompts
    for email + password on first run). Subsequent runs skip this.

14. **SSO not configured**
    -> /sso/login returns 501 with a clear message. Password login always
    works. SSO is a bonus, not a requirement.

15. **Report generation with no events**
    -> Returns a report with zero counts (not an error). The UI shows "no
    events in this period".

16. **Date range validation**
    -> start <= end. If start > end, return 400. If the range is > 90 days,
    return 400 (too large for MVP; paginate later).

17. **Cloud must not crash the proxy**
    -> The shipper is wrapped in try/except in the AuditLogger. A shipper
    error NEVER raises into the proxy. The proxy runs even if the cloud is
    down or the cloud URL is wrong.

18. **Circular dependency**
    -> The cloud package (mcp_shield/cloud/) imports NOTHING from the proxy
    pipeline (policy/detector/graph/approval). It only imports the AuditEntry
    shape (via a shared types module or by accepting a dict). The shipper
    (in the proxy) imports nothing from the cloud server code.

## 12. Test plan (concrete cases)

### 12.1 test_cloud_db.py

| Case | Input | Expected |
|---|---|---|
| init_db_creates_tables | fresh tmp db | all 4 tables exist |
| insert_event | one event | row in events table |
| query_events_by_org | two orgs, query org A | only org A events |
| idempotent_ingest | same (org,seq) twice | one row |
| revoked_key_rejected | insert with revoked key | 401 |
| user_password_hash | hash + verify | True on match, False on wrong |

### 12.2 test_cloud_rbac.py

| Case | Input | Expected |
|---|---|---|
| admin_can_all | admin role | all actions True |
| analyst_no_manage | analyst + manage_users | False |
| viewer_only_view | viewer + view_events | True; manage_users False |
| unknown_role | "superuser" | all False (deny by default) |

### 12.3 test_cloud_auth.py

| Case | Input | Expected |
|---|---|---|
| login_success | correct password | session cookie set |
| login_wrong_password | bad password | 401, no cookie |
| login_unknown_email | unknown email | 401 (same as wrong password) |
| session_valid | valid cookie | user returned |
| session_tampered | forged cookie | None (redirect to login) |
| logout | session then logout | cookie cleared |

### 12.4 test_cloud_ingest.py

| Case | Input | Expected |
|---|---|---|
| ingest_success | valid key + entries | 200, accepted=N |
| ingest_bad_key | unknown key | 401 |
| ingest_revoked_key | revoked key | 401 |
| ingest_idempotent | same seq twice | 1 row, 200 |
| ingest_no_auth | no Authorization header | 401 |
| ingest_rate_limit | >100 req/min | 429 |
| ingest_secrets_redacted | event with [REDACTED:] | stored as-is (no raw secret) |
| ingest_large_batch | 200 entries | 413 |

### 12.5 test_cloud_dashboard.py

| Case | Input | Expected |
|---|---|---|
| dashboard_requires_login | no session | redirect to /login |
| dashboard_shows_events | logged in + events | table with events |
| dashboard_filter_decision | filter deny | only deny events |
| dashboard_pagination | 60 events | 50 on page 1, 10 on page 2 |
| event_detail | click event | full detail with args/detection/chain |
| viewer_blocked_from_users | viewer GET /users | 403 |
| cross_org_isolation | user in org A | cannot see org B events (empty) |

### 12.6 test_cloud_reports.py

| Case | Input | Expected |
|---|---|---|
| soc2_summary | events with blocks | summary cards with counts |
| iso27001_controls | events | rows mapped to Annex A controls |
| 152fz_summary | events with db->send chains | PII exfiltration count |
| csv_download | any report | CSV content-type, rows |
| empty_period | no events | zero counts (not error) |
| bad_date_range | start > end | 400 |
| viewer_blocked | viewer GET /reports | 403 |

### 12.7 test_cloud_shipper.py (in the proxy package)

| Case | Input | Expected |
|---|---|---|
| ship_queues | entry | queue length 1 |
| flush_success | mock 200 | queue empty, returns 1 |
| flush_failure | mock 500 | queue kept, returns 0 |
| queue_overflow | 1001 entries | oldest dropped, length 1000 |
| shipper_never_raises | bad URL | no exception |
| disabled_noop | shipper=None | audit.log works, no ship

### 12.8 smoke_cloud.py (end-to-end)

- Start the cloud server on a random port with a tmp DB.
- Create an org + admin via the init command.
- POST events via /api/ingest with the API key.
- GET /dashboard (login first) -> see the events.
- GET /reports/soc2 -> see the summary.
- Verify a secret in the shipped event is [REDACTED:] in the DB.

## 13. Implementation order (bug-free sequence)

Each step is independently testable and green before the next. Phase 1-4
tests stay green throughout.

1. `cloud/models.py` - dataclasses (Org, User, Event). Test: import. GREEN.

2. `cloud/db.py` - SQLite schema + CRUD (init_db, insert_event,
   query_events, insert_user, get_user, insert_key, validate_key).
   Test: test_cloud_db.py (tmp_path). GREEN.

3. `cloud/rbac.py` - can(role, action). Test: test_cloud_rbac.py. GREEN.

4. `cloud/auth.py` - hash_password, verify_password, create_session,
   verify_session. Test: test_cloud_auth.py. GREEN.

5. `cloud/api_ingest.py` - POST /api/ingest (FastAPI router). Test:
   test_cloud_ingest.py (TestClient). GREEN.

6. `cloud/reports.py` - generate_report(org, framework, start, end).
   Test: test_cloud_reports.py. GREEN.

7. `cloud/dashboard.py` - Jinja2 templates + routes (login, dashboard,
   events, reports, users, keys). Test: test_cloud_dashboard.py. GREEN.

8. `cloud/server.py` - FastAPI app assembly (mount routers, session
   middleware, startup init_db). `mcp-shield-cloud` entry point.

9. `cloud/__init__.py` - public API.

10. `cloud/shipper.py` (in the PROXY package) - CloudShipper.
    Test: test_cloud_shipper.py. GREEN.

11. Integrate shipper into `audit.py` (optional shipper param) + `cli.py`
    (--cloud-url, --cloud-key). Test: Phase 1-4 suite still green
    (shipper disabled by default).

12. `pyproject.toml` - add `[cloud]` optional extra (fastapi, uvicorn,
    jinja2, python-multipart, itsdangerous). Update entry points.

13. `smoke_cloud.py` - end-to-end. GREEN.

14. README + docs + commit + push.

## 14. Dependencies

- **Core proxy: zero new mandatory deps.** The shipper uses `urllib` (stdlib).
  `--cloud-url` unset -> no new code runs.
- **Cloud server: new optional extra `[cloud]`.** Adds:
  - `fastapi>=0.104` (already in `[detector]`)
  - `uvicorn>=0.24` (already in `[detector]`)
  - `jinja2>=3.1`
  - `python-multipart>=0.0.6` (for login forms)
  - `itsdangerous>=2.1` (signed sessions; a Starlette dep already)
- Install with: `pip install mcp-shield[cloud]`.

## 15. Success criteria for Phase 5

- All Phase 1-4 tests pass unchanged (236 passed, 1 skipped) - no regression.
- New tests: 50+ across db/rbac/auth/ingest/dashboard/reports/shipper.
- smoke_cloud.py: ingest -> dashboard -> report end-to-end green.
- Proxy with --cloud-url disabled -> behaves exactly like Phase 1-4.
- Proxy with --cloud-url -> ships events; cloud unreachable -> no crash,
  local log still written.
- Multi-tenant isolation: org A cannot see org B events (tested).
- RBAC: viewer 403 on /users and /keys; analyst 403 on /users.
- Secrets: a raw secret in proxy args is [REDACTED:] in the cloud DB.
- Compliance reports: SOC2/ISO27001/152-ФЗ generate with correct counts.
- Cloud server crash + restart -> DB intact, proxy queue retries.
- No new mandatory dependencies in the core proxy.

## 16. File structure

```
mcp_shield/
  cloud/                      # the dashboard server (separate process)
    __init__.py
    models.py                 # Org, User, Event dataclasses
    db.py                     # SQLite schema + CRUD
    rbac.py                   # can(role, action)
    auth.py                   # password hash, session cookies, OIDC (optional)
    api_ingest.py             # POST /api/ingest (FastAPI router)
    reports.py                # SOC2/ISO27001/152-ФЗ report generators
    dashboard.py             # Jinja2 templates + dashboard routes
    server.py                 # FastAPI app assembly + mcp-shield-cloud entry
    templates/               # Jinja2 HTML templates
      base.html
      login.html
      dashboard.html
      event_detail.html
      reports.html
      users.html
      keys.html
  shipper.py                  # CloudShipper (in the PROXY, ships to cloud)
```

Changes to existing files:
- `audit.py` - optional `shipper` param; ship after each append (try/except).
- `cli.py` - `--cloud-url`, `--cloud-key` flags.
- `proxy.py` - ProxyConfig.cloud_url, cloud_key; pass shipper to AuditLogger.
- `pyproject.toml` - `[cloud]` optional extra; `mcp-shield-cloud` entry point.
- `README.md` - Phase 5 section + roadmap update.

## 17. CLI design (concrete)

### The proxy (unchanged except two new flags)

```
mcp-shield \
  --policy policies/default.yaml \
  --audit audit.jsonl \
  --detect-injection \
  --track-chains \
  --require-approval \
  --cloud-url https://dashboard.mcp-shield.io/api/ingest \
  --cloud-key mcp_live_abc123... \
  -- \
  npx -y @modelcontextprotocol/server-filesystem /home/me
```

### The cloud server

```
# Initialize (first run - creates DB + default org + admin user):
mcp-shield-cloud init --db ./mcp-shield.db --email admin@example.com

# Run the dashboard server:
mcp-shield-cloud serve --db ./mcp-shield.db --port 8080

# Open http://localhost:8080/login in a browser.
```

### Environment variables (optional, for SSO and prod)

```
MCP_SHIELD_OIDC_CLIENT_ID=...
MCP_SHIELD_OIDC_CLIENT_SECRET=...
MCP_SHIELD_OIDC_DISCOVERY_URL=https://login.microsoftonline.com/.../v2.0
MCP_SHIELD_SESSION_SECRET=...   # cookie signing secret (auto-generated if unset)
```
