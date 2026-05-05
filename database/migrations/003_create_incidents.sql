-- ============================================================================
-- Migration 003: Incident History
-- Records every alert processed by the orchestrator, the plans generated,
-- and the actions taken. Used by the Planning Agent to retrieve historical
-- context for similar threats (few-shot grounding for the LLM).
-- ============================================================================

CREATE TABLE IF NOT EXISTS incidents (
    id              SERIAL PRIMARY KEY,
    alert_id        VARCHAR(64) UNIQUE NOT NULL,      -- from anomaly-alerts topic
    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL,
    anomaly_score   FLOAT NOT NULL,
    classification  VARCHAR(100),                     -- e.g. "port_scan", "data_exfiltration"
    src_ip          INET,
    dst_ip          INET,
    dst_port        INTEGER,
    priority        VARCHAR(10),                      -- LOW, MEDIUM, HIGH, CRITICAL

    -- Aggregated context (JSON blobs for flexible storage)
    feature_vector  JSONB,                            -- raw features from detection layer
    cve_matches     JSONB,                            -- array of matched CVEs
    affected_assets JSONB,                            -- array of asset info
    threat_bundle   JSONB,                            -- full enriched context sent to LLM

    -- Plan & outcome
    plans_generated JSONB,                            -- all plans produced by LLM
    selected_plan_id VARCHAR(64),
    approval_status VARCHAR(20) DEFAULT 'pending',    -- pending, approved, rejected, escalated, timeout
    approved_by     VARCHAR(100),
    approval_notes  TEXT,

    -- Execution outcome
    execution_status VARCHAR(20) DEFAULT 'pending',   -- pending, executing, completed, partial_failure, failed
    execution_results JSONB,                          -- results from execution layer

    -- Lifecycle timestamps
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    triaged_at      TIMESTAMP WITH TIME ZONE,
    plans_ready_at  TIMESTAMP WITH TIME ZONE,
    approved_at     TIMESTAMP WITH TIME ZONE,
    executed_at     TIMESTAMP WITH TIME ZONE,
    closed_at       TIMESTAMP WITH TIME ZONE
);

-- Query patterns: find similar past incidents for LLM context
CREATE INDEX IF NOT EXISTS idx_incidents_classification ON incidents(classification);
CREATE INDEX IF NOT EXISTS idx_incidents_dst_port ON incidents(dst_port);
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents USING GIST(src_ip inet_ops);
CREATE INDEX IF NOT EXISTS idx_incidents_dst_ip ON incidents USING GIST(dst_ip inet_ops);
CREATE INDEX IF NOT EXISTS idx_incidents_score ON incidents(anomaly_score DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(approval_status);
