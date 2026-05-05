"""
Asset Inventory Seeder
=======================
Populates the asset database with sample hosts, services, and network zones
that match the IPs used in capture/generate_sample.py.

This provides the Asset Discovery Agent with realistic data to resolve IPs
against when processing anomaly alerts during development and testing.

Network topology seeded:
    10.0.0.0/24     → DMZ (web-facing servers)
    192.168.1.0/24  → Internal (corporate workstations)
    172.16.0.0/24   → External/Untrusted (simulated attacker range)

Usage:
    python database/seed/seed_assets.py
"""

import os
import psycopg2
from psycopg2.extras import execute_values

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://sentinel:sentinel_dev@localhost:5432/sentinel"
)


def seed():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # ── Network Zones ──────────────────────────────────────────────────────────
    zones = [
        ("dmz", "10.0.0.0/24", 100, 2, "Public-facing servers behind WAF"),
        ("internal", "192.168.1.0/24", 200, 3, "Corporate workstations and internal services"),
        ("management", "192.168.100.0/24", 300, 4, "Infrastructure management (switches, IPMI)"),
        ("external", "172.16.0.0/16", None, 1, "Untrusted external network range"),
    ]

    cur.execute("DELETE FROM asset_dependencies")
    cur.execute("DELETE FROM services")
    cur.execute("DELETE FROM assets")
    cur.execute("DELETE FROM network_zones")
    conn.commit()

    for zone_name, subnet, vlan_id, trust_level, desc in zones:
        cur.execute("""
            INSERT INTO network_zones (zone_name, subnet, vlan_id, trust_level, description)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (zone_name) DO UPDATE SET subnet=EXCLUDED.subnet
        """, (zone_name, subnet, vlan_id, trust_level, desc))
    conn.commit()

    # Get zone IDs
    cur.execute("SELECT id, zone_name FROM network_zones")
    zone_map = {name: zid for zid, name in cur.fetchall()}

    # ── Assets ─────────────────────────────────────────────────────────────────
    assets = [
        # DMZ servers (targets in generate_sample.py: 10.0.0.1)
        ("web-prod-01", "10.0.0.1", "AA:BB:CC:DD:01:01", "Ubuntu 22.04", "22.04.3 LTS",
         "infra-team", "Engineering", 2, "server", zone_map["dmz"]),
        ("web-prod-02", "10.0.0.2", "AA:BB:CC:DD:01:02", "Ubuntu 22.04", "22.04.3 LTS",
         "infra-team", "Engineering", 2, "server", zone_map["dmz"]),
        ("api-gateway", "10.0.0.10", "AA:BB:CC:DD:01:10", "Alpine 3.19", "3.19.1",
         "platform-team", "Engineering", 1, "server", zone_map["dmz"]),
        ("dns-resolver", "10.0.0.53", "AA:BB:CC:DD:01:53", "Ubuntu 22.04", "22.04.3 LTS",
         "infra-team", "Engineering", 2, "server", zone_map["dmz"]),

        # Internal workstations (sources in generate_sample.py: 192.168.1.x)
        ("dev-workstation-01", "192.168.1.10", "AA:BB:CC:DD:02:10", "macOS 14", "14.2",
         "alice", "Engineering", 4, "workstation", zone_map["internal"]),
        ("dev-workstation-02", "192.168.1.11", "AA:BB:CC:DD:02:11", "Ubuntu 22.04", "22.04.3 LTS",
         "bob", "Engineering", 4, "workstation", zone_map["internal"]),
        ("dev-workstation-03", "192.168.1.12", "AA:BB:CC:DD:02:12", "Windows 11", "23H2",
         "charlie", "Engineering", 4, "workstation", zone_map["internal"]),
        ("hr-workstation-01", "192.168.1.50", "AA:BB:CC:DD:02:50", "Windows 11", "23H2",
         "diana", "HR", 4, "workstation", zone_map["internal"]),
        ("db-internal", "192.168.1.100", "AA:BB:CC:DD:02:A0", "Ubuntu 22.04", "22.04.3 LTS",
         "infra-team", "Engineering", 1, "server", zone_map["internal"]),
        ("auth-server", "192.168.1.200", "AA:BB:CC:DD:02:C8", "Ubuntu 22.04", "22.04.3 LTS",
         "security-team", "Security", 1, "server", zone_map["internal"]),

        # Management
        ("switch-core-01", "192.168.100.1", "AA:BB:CC:DD:03:01", "Cisco IOS", "17.9",
         "network-team", "Infrastructure", 1, "network_device", zone_map["management"]),
        ("monitoring-srv", "192.168.100.10", "AA:BB:CC:DD:03:0A", "Ubuntu 22.04", "22.04.3 LTS",
         "infra-team", "Infrastructure", 2, "server", zone_map["management"]),
    ]

    for (hostname, ip, mac, os_name, os_ver, owner, dept, crit, atype, zone_id) in assets:
        cur.execute("""
            INSERT INTO assets (hostname, ip_address, mac_address, os, os_version,
                                owner, department, criticality_tier, asset_type, zone_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (hostname) DO UPDATE SET ip_address=EXCLUDED.ip_address
        """, (hostname, ip, mac, os_name, os_ver, owner, dept, crit, atype, zone_id))
    conn.commit()

    # Get asset IDs
    cur.execute("SELECT id, hostname FROM assets")
    asset_map = {name: aid for aid, name in cur.fetchall()}

    # ── Services ───────────────────────────────────────────────────────────────
    services = [
        # web-prod-01: the primary target of port scans in sample.pcap
        (asset_map["web-prod-01"], 22, "tcp", "openssh", "9.5p1", True),
        (asset_map["web-prod-01"], 80, "tcp", "nginx", "1.24.0", True),
        (asset_map["web-prod-01"], 443, "tcp", "nginx", "1.24.0", True),

        (asset_map["web-prod-02"], 22, "tcp", "openssh", "9.5p1", True),
        (asset_map["web-prod-02"], 443, "tcp", "nginx", "1.24.0", True),

        (asset_map["api-gateway"], 443, "tcp", "envoy", "1.28.0", True),
        (asset_map["api-gateway"], 8443, "tcp", "envoy", "1.28.0", False),

        (asset_map["dns-resolver"], 53, "udp", "bind9", "9.18.24", True),
        (asset_map["dns-resolver"], 53, "tcp", "bind9", "9.18.24", True),

        (asset_map["db-internal"], 5432, "tcp", "postgresql", "16.1", False),
        (asset_map["auth-server"], 636, "tcp", "openldap", "2.6.7", False),
        (asset_map["auth-server"], 8443, "tcp", "keycloak", "23.0.4", False),

        (asset_map["monitoring-srv"], 9090, "tcp", "prometheus", "2.49.0", False),
        (asset_map["monitoring-srv"], 3000, "tcp", "grafana", "10.3.1", False),
    ]

    for (asset_id, port, proto, svc_name, version, exposed) in services:
        cur.execute("""
            INSERT INTO services (asset_id, port, protocol, service_name, version, is_exposed)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (asset_id, port, protocol) DO UPDATE SET version=EXCLUDED.version
        """, (asset_id, port, proto, svc_name, version, exposed))
    conn.commit()

    # ── Dependencies (for blast radius) ────────────────────────────────────────
    dependencies = [
        # web-prod-01 depends on db-internal and auth-server
        (asset_map["db-internal"], asset_map["web-prod-01"], "database", True),
        (asset_map["auth-server"], asset_map["web-prod-01"], "auth", True),
        (asset_map["auth-server"], asset_map["web-prod-02"], "auth", True),
        (asset_map["db-internal"], asset_map["api-gateway"], "database", True),
        (asset_map["auth-server"], asset_map["api-gateway"], "auth", True),
        (asset_map["dns-resolver"], asset_map["web-prod-01"], "dns", False),
        (asset_map["dns-resolver"], asset_map["web-prod-02"], "dns", False),
    ]

    for (upstream, downstream, dep_type, critical) in dependencies:
        cur.execute("""
            INSERT INTO asset_dependencies (upstream_id, downstream_id, dependency_type, is_critical)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (upstream_id, downstream_id) DO NOTHING
        """, (upstream, downstream, dep_type, critical))
    conn.commit()

    cur.close()
    conn.close()
    print(f"Seeded: {len(zones)} zones, {len(assets)} assets, {len(services)} services, {len(dependencies)} dependencies")


if __name__ == "__main__":
    seed()
