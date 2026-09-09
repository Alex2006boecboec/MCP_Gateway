-- Migration 004: Rate limit buckets table
-- For persistent rate limiting across multiple workers/processes.
-- Currently using in-memory limiter; this table is for future use.

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    bucket_key TEXT NOT NULL,
    window_start DOUBLE PRECISION NOT NULL,
    count INTEGER DEFAULT 0,
    PRIMARY KEY (bucket_key, window_start)
);
CREATE INDEX IF NOT EXISTS rate_limit_buckets_key ON rate_limit_buckets(bucket_key);
