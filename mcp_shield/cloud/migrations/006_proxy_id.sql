-- Multi-proxy event dedup: uniqueness is (org_id, proxy_id, seq).
-- Older unique index on (org_id, seq) dropped events from a second proxy.
ALTER TABLE events ADD COLUMN IF NOT EXISTS proxy_id TEXT NOT NULL DEFAULT '';
DROP INDEX IF EXISTS events_org_seq_unique;
CREATE UNIQUE INDEX IF NOT EXISTS events_org_proxy_seq_unique
    ON events(org_id, proxy_id, seq) WHERE seq IS NOT NULL;
