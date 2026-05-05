-- ============================================================================
-- Migration 002: Asset Inventory Tables
-- Three tables model the network: hosts (machines), services (what runs on
-- them), and network_zones (logical segmentation). The Asset Discovery Agent
-- queries these to determine what's affected by a detected anomaly and
-- calculate blast radius.
-- ============================================================================

-- Hosts: physical or virtual machines on the network
CREATE TABLE IF NOT EXISTS assets (
    id              SERIAL PRIMARY KEY,
    hostname        VARCHAR(255) UNIQUE NOT NULL,
    ip_address      INET NOT NULL,                    -- supports IPv4 and IPv6
    mac_address     MACADDR,
    os              VARCHAR(100),                     -- e.g. "Ubuntu 22.04", "Windows Server 2022"
    os_version      VARCHAR(50),
    owner           VARCHAR(100),                     -- responsible person/team
    department      VARCHAR(100),
    criticality_tier INTEGER NOT NULL CHECK (criticality_tier BETWEEN 1 AND 5),
        -- 1 = mission-critical (e.g. auth server)
        -- 2 = high (production web)
        -- 3 = medium (internal tooling)
        -- 4 = low (dev/staging)
        -- 5 = negligible (test VMs)
    asset_type      VARCHAR(50),                      -- server, workstation, IoT, network_device
    last_vuln_scan  TIMESTAMP WITH TIME ZONE,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets USING GIST(ip_address inet_ops);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality_tier);
CREATE INDEX IF NOT EXISTS idx_assets_active ON assets(is_active) WHERE is_active = TRUE;

-- Services: what runs on each host (port + software + version)
CREATE TABLE IF NOT EXISTS services (
    id              SERIAL PRIMARY KEY,
    asset_id        INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol        VARCHAR(10) NOT NULL DEFAULT 'tcp',  -- tcp, udp
    service_name    VARCHAR(100) NOT NULL,            -- e.g. "openssh", "nginx", "postgresql"
    version         VARCHAR(50),                      -- e.g. "9.5p1", "1.24.0"
    is_exposed      BOOLEAN DEFAULT FALSE,            -- externally reachable?
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_services_asset ON services(asset_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);
CREATE INDEX IF NOT EXISTS idx_services_name ON services(service_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_services_unique ON services(asset_id, port, protocol);

-- Network zones: logical segmentation (VLANs, subnets, trust boundaries)
CREATE TABLE IF NOT EXISTS network_zones (
    id              SERIAL PRIMARY KEY,
    zone_name       VARCHAR(100) UNIQUE NOT NULL,     -- e.g. "dmz", "internal", "mgmt"
    subnet          CIDR NOT NULL,                    -- e.g. 10.0.0.0/24
    vlan_id         INTEGER,
    trust_level     INTEGER NOT NULL CHECK (trust_level BETWEEN 1 AND 5),
        -- 1 = untrusted (public-facing)
        -- 2 = semi-trusted (DMZ)
        -- 3 = trusted (internal)
        -- 4 = highly trusted (management)
        -- 5 = restricted (secrets/auth infrastructure)
    description     TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_zones_subnet ON network_zones USING GIST(subnet inet_ops);

-- Map assets to zones (an asset lives in one zone)
ALTER TABLE assets ADD COLUMN IF NOT EXISTS zone_id INTEGER REFERENCES network_zones(id);
CREATE INDEX IF NOT EXISTS idx_assets_zone ON assets(zone_id);

-- Dependencies: which assets depend on which (for blast radius calculation)
CREATE TABLE IF NOT EXISTS asset_dependencies (
    id              SERIAL PRIMARY KEY,
    upstream_id     INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    downstream_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    dependency_type VARCHAR(50),                      -- e.g. "database", "api", "auth"
    is_critical     BOOLEAN DEFAULT FALSE,            -- failure = downstream breaks
    UNIQUE(upstream_id, downstream_id)
);

CREATE INDEX IF NOT EXISTS idx_deps_upstream ON asset_dependencies(upstream_id);
CREATE INDEX IF NOT EXISTS idx_deps_downstream ON asset_dependencies(downstream_id);
