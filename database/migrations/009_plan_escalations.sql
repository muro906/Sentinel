-- 009: Plan escalation tracking table
-- Persists escalation requests so they survive page refreshes and WS reconnects

CREATE TABLE IF NOT EXISTS plan_escalations (
    id              SERIAL PRIMARY KEY,
    alert_id        VARCHAR(100)    NOT NULL,
    plan_id         VARCHAR(255)    NOT NULL,
    escalated_by    VARCHAR(100)    NOT NULL,   -- analyst who escalated
    reason          TEXT            NOT NULL,
    actions         JSONB           NOT NULL DEFAULT '[]',
    status          VARCHAR(12)     NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'picked_up', 'resolved', 'cancelled')),
    picked_up_by    VARCHAR(100),               -- admin/senior who claimed it
    picked_up_at    TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT fk_esc_alert FOREIGN KEY (alert_id)
        REFERENCES incidents(alert_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_esc_alert_id    ON plan_escalations(alert_id);
CREATE INDEX IF NOT EXISTS idx_esc_status      ON plan_escalations(status);
CREATE INDEX IF NOT EXISTS idx_esc_escalated_by ON plan_escalations(escalated_by);
