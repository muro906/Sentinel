-- Database schema for Sentinel Dashboard

-- Network zones for asset segmentation
CREATE TABLE IF NOT EXISTS network_zones (
    id SERIAL PRIMARY KEY,
    zone_name VARCHAR(50) NOT NULL UNIQUE,
    trust_level VARCHAR(20) NOT NULL
);

-- Asset inventory
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    os VARCHAR(100),
    asset_type VARCHAR(50),
    criticality_tier INTEGER DEFAULT 3,
    is_active BOOLEAN DEFAULT TRUE,
    zone_id INTEGER REFERENCES network_zones(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Services running on assets
CREATE TABLE IF NOT EXISTS services (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp',
    service_name VARCHAR(100),
    version VARCHAR(50),
    is_exposed BOOLEAN DEFAULT FALSE
);

-- Security incidents/alerts
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(100) NOT NULL UNIQUE,
    classification VARCHAR(255),
    priority VARCHAR(20) DEFAULT 'medium',
    approval_status VARCHAR(50) DEFAULT 'received',
    execution_status VARCHAR(50) DEFAULT 'pending',
    src_ip INET,
    dst_ip INET,
    dst_port INTEGER,
    anomaly_score FLOAT,
    plans_generated JSONB,
    approved_by VARCHAR(100),
    approved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    triaged_at TIMESTAMP,
    plans_ready_at TIMESTAMP,
    executed_at TIMESTAMP,
    closed_at TIMESTAMP
);

-- Plan approvals record
CREATE TABLE IF NOT EXISTS approvals (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(100) REFERENCES incidents(alert_id),
    plan_id VARCHAR(100),
    decision VARCHAR(20) NOT NULL,
    approved_by VARCHAR(100) NOT NULL,
    actions JSONB DEFAULT '[]',
    notes TEXT,
    modifications TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Agent reasoning traces
CREATE TABLE IF NOT EXISTS reasoning_traces (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(50) NOT NULL,
    alert_id VARCHAR(100) REFERENCES incidents(alert_id),
    event_type VARCHAR(50),
    agent_name VARCHAR(50),
    action VARCHAR(100),
    rationale TEXT,
    input_summary TEXT,
    output_summary TEXT,
    confidence FLOAT,
    duration_ms INTEGER,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- CVE database
CREATE TABLE IF NOT EXISTS cve_entries (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    description TEXT,
    cvss_v3_score FLOAT,
    severity VARCHAR(20),
    affected_vendor VARCHAR(100),
    affected_product VARCHAR(200),
    attack_vector VARCHAR(50),
    exploit_available BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- User accounts
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(approval_status);
CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_traces_alert ON reasoning_traces(alert_id);
CREATE INDEX IF NOT EXISTS idx_assets_zone ON assets(zone_id);
CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_entries(cvss_v3_score DESC);
