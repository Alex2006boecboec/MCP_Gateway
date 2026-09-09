-- Migration 002: Password resets table
-- Used for password reset flow (/forgot, /reset).

CREATE TABLE IF NOT EXISTS password_resets (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    expires_at DOUBLE PRECISION NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at DOUBLE PRECISION NOT NULL
);
