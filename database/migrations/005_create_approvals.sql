CREATE TABLE IF NOT EXISTS approvals (
    id            SERIAL PRIMARY KEY,
    alert_id      VARCHAR(64) NOT NULL REFERENCES incidents(alert_id) ON DELETE CASCADE,
    plan_id       VARCHAR(64) NOT NULL,
    decision      VARCHAR(10) NOT NULL CHECK (decision IN ('approved','rejected')),
    approved_by   VARCHAR(100) NOT NULL,  -- always from JWT sub — cannot be forged
    actions       JSONB,
    modifications TEXT,
    notes         TEXT,
    decided_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_approvals_alert    ON approvals(alert_id);
CREATE INDEX IF NOT EXISTS idx_approvals_user     ON approvals(approved_by);
CREATE INDEX IF NOT EXISTS idx_approvals_time     ON approvals(decided_at DESC);