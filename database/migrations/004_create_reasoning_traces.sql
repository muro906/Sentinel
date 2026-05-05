-- ============================================================================
-- Migration 004: Reasoning Traces
-- Persists every reasoning step from every agent for audit, review, and
-- display to the SOC analyst. Each row is a single event in the agent's
-- decision chain. Analysts can drill into any alert and see exactly WHY
-- decisions were made.
-- ============================================================================

CREATE TABLE IF NOT EXISTS reasoning_traces (
    id              SERIAL PRIMARY KEY,
    event_id        VARCHAR(64) UNIQUE NOT NULL,
    alert_id        VARCHAR(64) NOT NULL,             -- FK conceptual to incidents.alert_id
    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Which agent emitted this event
    agent           VARCHAR(50) NOT NULL,             -- orchestrator, cve_lookup, asset_discovery, planning
    event_type      VARCHAR(50) NOT NULL,             -- alert_received, triage_decision, agent_dispatched, etc.

    -- What happened
    action          VARCHAR(200) NOT NULL,            -- human-readable description of the action
    input_summary   TEXT,                             -- condensed input (for timeline display)
    output_summary  TEXT,                             -- condensed output (for timeline display)
    full_input      JSONB,                            -- complete input data (expandable in UI)
    full_output     JSONB,                            -- complete output data (expandable in UI)

    -- Decision rationale (THE KEY FIELD for analyst transparency)
    rationale       TEXT NOT NULL,                    -- WHY this decision was made

    -- Metadata
    duration_ms     INTEGER,                          -- how long this step took
    confidence      FLOAT,                            -- if applicable (0.0-1.0)
    error           TEXT,                             -- if this step failed

    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Query patterns: get full trace for an alert, ordered by time
CREATE INDEX IF NOT EXISTS idx_traces_alert_id ON reasoning_traces(alert_id);
CREATE INDEX IF NOT EXISTS idx_traces_timestamp ON reasoning_traces(alert_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_agent ON reasoning_traces(agent);
CREATE INDEX IF NOT EXISTS idx_traces_event_type ON reasoning_traces(event_type);
