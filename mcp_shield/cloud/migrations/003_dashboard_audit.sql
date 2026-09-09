-- Migration 003: Dashboard action audit log
-- Records all state-changing actions (user create/delete, role change,
-- key create/revoke, password change/reset) for compliance.

CREATE TABLE IF NOT EXISTS dashboard_actions (
    id SERIAL PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    actor_id TEXT NOT NULL REFERENCES users(id),
    actor_email TEXT,
    action TEXT NOT NULL,          -- 'user.create', 'user.delete', etc.
    target_type TEXT,              -- 'user', 'api_key', 'org'
    target_id TEXT,
    detail TEXT,                   -- JSON with extra context
    created_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS dashboard_actions_org ON dashboard_actions(org_id, created_at);
