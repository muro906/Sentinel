-- ============================================================================
-- Migration 010: Add investigation_started_at to incidents
-- Tracks when a user clicked "Start Investigation" for an alert.
-- ============================================================================

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS investigation_started_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_incidents_investigation_started
    ON incidents(investigation_started_at)
    WHERE investigation_started_at IS NOT NULL;
