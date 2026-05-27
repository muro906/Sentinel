-- ============================================================================
-- Migration 007: Add missing columns and tables
-- Adds:
--   • users.email, users.status
--   • incidents.assigned_to
--   • role_change_requests table
--   • password_reset_tokens table
-- ============================================================================

-- ── users: add email and status ───────────────────────────────────────────
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email  TEXT,
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'approved';

CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- ── incidents: add assigned_to ────────────────────────────────────────────
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(100);

CREATE INDEX IF NOT EXISTS idx_incidents_assigned ON incidents(assigned_to);

-- ── role_change_requests ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS role_change_requests (
    id             SERIAL PRIMARY KEY,
    username       VARCHAR(100) NOT NULL,
    "current_role" VARCHAR(20)  NOT NULL,
    requested_role VARCHAR(20)  NOT NULL,
    reason         TEXT         NOT NULL,
    status         VARCHAR(10)  NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'approved', 'denied')),
    admin_notes    TEXT,
    processed_by   VARCHAR(100),
    processed_at   TIMESTAMP WITH TIME ZONE,
    created_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rcr_username ON role_change_requests(username);
CREATE INDEX IF NOT EXISTS idx_rcr_status   ON role_change_requests(status);

-- ── password_reset_tokens ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(100) NOT NULL,
    token_hash  VARCHAR(128) NOT NULL UNIQUE,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    used        BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_prt_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_prt_username   ON password_reset_tokens(username);
