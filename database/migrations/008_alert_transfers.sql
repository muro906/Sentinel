-- 008: Alert transfer requests table
-- Tracks peer-to-peer alert transfer requests between analysts

CREATE TABLE IF NOT EXISTS alert_transfer_requests (
    id              SERIAL PRIMARY KEY,
    alert_id        VARCHAR(100)    NOT NULL,
    from_user       VARCHAR(100)    NOT NULL,  -- who wants to transfer away
    to_user         VARCHAR(100)    NOT NULL,  -- who should receive it
    reason          TEXT            NOT NULL,
    status          VARCHAR(12)     NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled')),
    responded_at    TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT fk_transfer_alert FOREIGN KEY (alert_id)
        REFERENCES incidents(alert_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_atr_alert_id  ON alert_transfer_requests(alert_id);
CREATE INDEX IF NOT EXISTS idx_atr_to_user   ON alert_transfer_requests(to_user);
CREATE INDEX IF NOT EXISTS idx_atr_from_user ON alert_transfer_requests(from_user);
CREATE INDEX IF NOT EXISTS idx_atr_status    ON alert_transfer_requests(status);
