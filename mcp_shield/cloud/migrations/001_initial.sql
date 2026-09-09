-- Migration 001: Initial schema for PostgreSQL
-- Creates all tables for the MCP Shield cloud dashboard.

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
    scopes JSONB DEFAULT '["ingest"]'::jsonb
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

-- Track which migrations have been applied.
CREATE TABLE IF NOT EXISTS schema_migrations (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at DOUBLE PRECISION NOT NULL
);
