-- ============================================================================
-- Migration 001: CVE Entries Table
-- Stores mirrored CVE data from NIST NVD for offline lookup by the CVE agent.
-- Uses full-text search (tsvector) for fast keyword matching against traffic
-- signatures, and pgvector for optional semantic similarity search.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS cve_entries (
    id              SERIAL PRIMARY KEY,
    cve_id          VARCHAR(20) UNIQUE NOT NULL,      -- e.g. CVE-2024-12345
    description     TEXT NOT NULL,
    cvss_v3_score   FLOAT,                            -- 0.0 - 10.0
    cvss_v3_vector  VARCHAR(100),                     -- e.g. CVSS:3.1/AV:N/AC:L/...
    severity        VARCHAR(10),                      -- LOW, MEDIUM, HIGH, CRITICAL
    published_date  TIMESTAMP WITH TIME ZONE,
    modified_date   TIMESTAMP WITH TIME ZONE,

    -- Affected product metadata (CPE-based)
    affected_vendor   VARCHAR(100),                   -- e.g. "openssh"
    affected_product  VARCHAR(100),                   -- e.g. "openssh_server"
    affected_versions TEXT,                           -- version range string

    -- Attack characteristics for signature matching
    attack_vector     VARCHAR(20),                    -- NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity VARCHAR(10),                    -- LOW, HIGH
    privileges_required VARCHAR(10),                  -- NONE, LOW, HIGH
    user_interaction  VARCHAR(10),                    -- NONE, REQUIRED

    -- Exploit metadata
    exploit_available   BOOLEAN DEFAULT FALSE,
    exploit_description TEXT,

    -- Full-text search column (auto-populated via trigger)
    search_vector   TSVECTOR,

    -- Semantic embedding for pgvector similarity search (optional)
    embedding       vector(384),                     -- all-MiniLM-L6-v2 dimension

    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Full-text search index for keyword matching
CREATE INDEX IF NOT EXISTS idx_cve_search_vector
    ON cve_entries USING GIN(search_vector);

-- Semantic similarity index (IVFFlat for approximate nearest neighbor)
CREATE INDEX IF NOT EXISTS idx_cve_embedding
    ON cve_entries USING ivfflat(embedding vector_cosine_ops) WITH (lists = 100);

-- Lookup indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity);
CREATE INDEX IF NOT EXISTS idx_cve_vendor ON cve_entries(affected_vendor);
CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_entries(affected_product);
CREATE INDEX IF NOT EXISTS idx_cve_attack_vector ON cve_entries(attack_vector);
CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_entries(cvss_v3_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_exploit ON cve_entries(exploit_available) WHERE exploit_available = TRUE;

-- Auto-populate the tsvector column on INSERT/UPDATE
CREATE OR REPLACE FUNCTION update_cve_search_vector()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        COALESCE(NEW.cve_id, '') || ' ' ||
        COALESCE(NEW.description, '') || ' ' ||
        COALESCE(NEW.affected_vendor, '') || ' ' ||
        COALESCE(NEW.affected_product, '') || ' ' ||
        COALESCE(NEW.affected_versions, '') || ' ' ||
        COALESCE(NEW.exploit_description, '')
    );
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_cve_search_vector
    BEFORE INSERT OR UPDATE ON cve_entries
    FOR EACH ROW
    EXECUTE FUNCTION update_cve_search_vector();
