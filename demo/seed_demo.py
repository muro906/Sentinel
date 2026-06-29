"""
Sentinel Demo Seeder
====================
Populates the database with a realistic mock network topology, asset inventory,
and CVE entries so the full agent pipeline produces meaningful output during demos.

Usage (from project root, with postgres running):
    docker-compose exec postgres psql -U sentinel -d sentinel  # verify DB up
    python demo/seed_demo.py

Or against a local postgres:
    DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/sentinel python demo/seed_demo.py
"""

import asyncio
import os
import sys
from datetime import datetime, timezone

import asyncpg

DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel_dev@localhost:5433/sentinel")


# ── Network topology ──────────────────────────────────────────────────────────

ZONES = [
    # (zone_name, subnet, vlan_id, trust_level, description)
    ("internet",    "0.0.0.0/0",      None, 1, "Untrusted external internet"),
    ("dmz",         "10.10.1.0/24",   10,   2, "Perimeter zone — public-facing services"),
    ("internal",    "10.10.2.0/24",   20,   3, "Internal application and data servers"),
    ("management",  "10.10.3.0/24",   30,   4, "Management network — analyst workstations"),
]

ASSETS = [
    # (hostname, ip, mac, os, os_version, owner, dept, crit_tier, asset_type, zone_name)
    ("edge-router-01",  "10.10.0.1",   None,
     "Cisco IOS", "15.9", "netops", "Infrastructure", 2, "network_device", "dmz"),
    ("core-switch-01",  "10.10.0.2",   None,
     "Cisco NX-OS", "9.3", "netops", "Infrastructure", 3, "network_device", "internal"),
    ("web-server-01",   "10.10.1.10",  "aa:bb:cc:01:01:01",
     "Ubuntu", "22.04 LTS", "webops", "Engineering", 1, "server", "dmz"),
    ("app-server-01",   "10.10.2.10",  "aa:bb:cc:02:01:01",
     "Ubuntu", "22.04 LTS", "appops", "Engineering", 1, "server", "internal"),
    ("file-server-01",  "10.10.2.20",  "aa:bb:cc:02:02:01",
     "Windows Server", "2019", "sysadmin", "IT", 1, "server", "internal"),
    ("analyst-ws-01",   "10.10.3.100", "aa:bb:cc:03:01:01",
     "Ubuntu", "22.04 LTS", "analyst1", "SOC", 3, "workstation", "management"),
]

# (hostname, port, protocol, service_name, version, is_exposed)
SERVICES = {
    "web-server-01": [
        (80,   "tcp", "nginx",   "1.24.0", True),
        (443,  "tcp", "nginx",   "1.24.0", True),
        (22,   "tcp", "openssh", "8.9p1",  False),
    ],
    "app-server-01": [
        (8080, "tcp", "apache-tomcat", "9.0.75",  False),
        (3306, "tcp", "mysql",         "8.0.33",  False),
        (22,   "tcp", "openssh",       "8.9p1",   False),
    ],
    "file-server-01": [
        (445,  "tcp", "samba",   "4.17",   False),
        (3389, "tcp", "rdp",     "10.0",   False),
        (5985, "tcp", "winrm",   "3.0",    False),
    ],
    "analyst-ws-01": [
        (22,   "tcp", "openssh", "8.9p1",  False),
        (3389, "tcp", "rdp",     "10.0",   False),
    ],
}

# ── CVE entries ───────────────────────────────────────────────────────────────
# Chosen so they match what the CVE lookup agent queries:
#   affected_product ILIKE %<service_from_port>%  OR  description ILIKE %<classification>%

CVES = [
    # Log4Shell — matches http_exploit classification + "http" product search
    {
        "cve_id": "CVE-2021-44228",
        "description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features allow remote code execution "
            "via crafted HTTP requests (Log4Shell). Widely exploited via http_exploit payloads "
            "in User-Agent and X-Api-Version headers against web servers."
        ),
        "cvss_v3_score": 10.0,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "affected_vendor": "apache",
        "affected_product": "log4j http log4j2",
        "affected_versions": "2.0-beta9 to 2.14.1",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "exploit_available": True,
        "exploit_description": "Public PoC and mass exploitation observed in Dec 2021.",
    },
    # Apache Path Traversal — matches nginx/http on port 80/443
    {
        "cve_id": "CVE-2021-41773",
        "description": (
            "Path traversal and remote code execution in Apache HTTP Server 2.4.49. "
            "Allows unauthenticated attacker to map URLs to files outside the document root "
            "via http_exploit crafted request paths."
        ),
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "affected_vendor": "apache",
        "affected_product": "http_server nginx apache http",
        "affected_versions": "2.4.49",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "exploit_available": True,
        "exploit_description": "CVSSv3 9.8; weaponised within days of disclosure.",
    },
    # EternalBlue — matches smb on port 445
    {
        "cve_id": "CVE-2017-0144",
        "description": (
            "Windows SMBv1 remote code execution (EternalBlue / WannaCry). "
            "The smb_exploit sends malformed SMBv1 packets to port 445, "
            "allowing unauthenticated kernel-level code execution on Windows hosts."
        ),
        "cvss_v3_score": 9.3,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "affected_vendor": "microsoft",
        "affected_product": "smb windows samba smb_exploit",
        "affected_versions": "Windows 7, 8.1, Server 2008 R2, 2012, 2016",
        "attack_vector": "NETWORK",
        "attack_complexity": "HIGH",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "exploit_available": True,
        "exploit_description": "NSA-leaked exploit, used by WannaCry ransomware.",
    },
    # Zerologon — also matches smb/windows
    {
        "cve_id": "CVE-2020-1472",
        "description": (
            "Netlogon privilege escalation (Zerologon) allows an attacker on the network "
            "to compromise a Windows domain controller via smb_exploit Netlogon RPC calls "
            "using weak cryptography on port 445 and 135."
        ),
        "cvss_v3_score": 10.0,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "affected_vendor": "microsoft",
        "affected_product": "smb netlogon windows active_directory",
        "affected_versions": "Windows Server 2008 through 2019",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "exploit_available": True,
        "exploit_description": "PoC published by Secura BV; full domain compromise in seconds.",
    },
    # BlueKeep — matches rdp on port 3389
    {
        "cve_id": "CVE-2019-0708",
        "description": (
            "Remote Desktop Services (RDP) pre-auth remote code execution (BlueKeep). "
            "An rdp_exploit request to port 3389 on a vulnerable Windows system can achieve "
            "unauthenticated kernel-level code execution — no interaction required."
        ),
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "affected_vendor": "microsoft",
        "affected_product": "rdp remote_desktop windows rdp_exploit",
        "affected_versions": "Windows 7, Server 2003/2008 R2",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "exploit_available": True,
        "exploit_description": "MSF module available; NSA flagged as wormable.",
    },
    # OpenSSH vulns — matches ssh on port 22
    {
        "cve_id": "CVE-2023-38408",
        "description": (
            "OpenSSH ssh-agent remote code execution via malicious agent forwarding. "
            "ssh_brute_force or compromised SSH sessions can leverage forwarded agents "
            "to trigger arbitrary code execution in the agent process."
        ),
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "affected_vendor": "openbsd",
        "affected_product": "openssh ssh ssh_brute_force",
        "affected_versions": "OpenSSH before 9.3p2",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "exploit_available": True,
        "exploit_description": "PoC published; requires an active forwarded agent.",
    },
    # MySQL / SQL injection via port 3306
    {
        "cve_id": "CVE-2023-21980",
        "description": (
            "MySQL Server vulnerability allowing remote privileged attacker to cause "
            "data_exfiltration or compromise via crafted protocol requests to port 3306. "
            "Affects MySQL 8.0 community and enterprise editions."
        ),
        "cvss_v3_score": 7.7,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "severity": "HIGH",
        "affected_vendor": "oracle",
        "affected_product": "mysql data_exfiltration database",
        "affected_versions": "MySQL 8.0 < 8.0.33",
        "attack_vector": "NETWORK",
        "attack_complexity": "HIGH",
        "privileges_required": "LOW",
        "user_interaction": "NONE",
        "exploit_available": False,
        "exploit_description": "Oracle patched in April 2023 CPU.",
    },
]


# ── DB helpers ────────────────────────────────────────────────────────────────

async def seed(conn: asyncpg.Connection) -> None:
    print("Seeding network zones…")
    zone_ids: dict[str, int] = {}
    for zone_name, subnet, vlan_id, trust_level, description in ZONES:
        zid = await conn.fetchval(
            """
            INSERT INTO network_zones (zone_name, subnet, vlan_id, trust_level, description)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (zone_name) DO UPDATE SET description=EXCLUDED.description
            RETURNING id
            """,
            zone_name, subnet, vlan_id, trust_level, description,
        )
        zone_ids[zone_name] = zid
    print(f"  {len(ZONES)} zones ready")

    print("Seeding assets…")
    asset_ids: dict[str, int] = {}
    for (hostname, ip, mac, os_name, os_ver, owner, dept,
         crit_tier, asset_type, zone_name) in ASSETS:
        aid = await conn.fetchval(
            """
            INSERT INTO assets
                (hostname, ip_address, mac_address, os, os_version,
                 owner, department, criticality_tier, asset_type, zone_id, is_active)
            VALUES ($1, $2::inet, $3::macaddr, $4, $5, $6, $7, $8, $9, $10, TRUE)
            ON CONFLICT (hostname) DO UPDATE
                SET ip_address=EXCLUDED.ip_address, os=EXCLUDED.os,
                    criticality_tier=EXCLUDED.criticality_tier, zone_id=EXCLUDED.zone_id
            RETURNING id
            """,
            hostname, ip,
            mac,
            os_name, os_ver, owner, dept,
            crit_tier, asset_type, zone_ids.get(zone_name),
        )
        asset_ids[hostname] = aid
    print(f"  {len(ASSETS)} assets ready")

    print("Seeding services…")
    svc_count = 0
    for hostname, svcs in SERVICES.items():
        aid = asset_ids.get(hostname)
        if aid is None:
            continue
        for (port, proto, svc_name, version, is_exposed) in svcs:
            await conn.execute(
                """
                INSERT INTO services
                    (asset_id, port, protocol, service_name, version, is_exposed)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (asset_id, port, protocol) DO UPDATE
                    SET service_name=EXCLUDED.service_name, version=EXCLUDED.version
                """,
                aid, port, proto, svc_name, version, is_exposed,
            )
            svc_count += 1
    print(f"  {svc_count} services ready")

    print("Seeding CVEs…")
    for cve in CVES:
        await conn.execute(
            """
            INSERT INTO cve_entries (
                cve_id, description, cvss_v3_score, cvss_v3_vector, severity,
                affected_vendor, affected_product, affected_versions,
                attack_vector, attack_complexity, privileges_required,
                user_interaction, exploit_available, exploit_description
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            ON CONFLICT (cve_id) DO UPDATE SET
                description=EXCLUDED.description,
                cvss_v3_score=EXCLUDED.cvss_v3_score,
                affected_product=EXCLUDED.affected_product,
                exploit_available=EXCLUDED.exploit_available
            """,
            cve["cve_id"], cve["description"], cve["cvss_v3_score"],
            cve["cvss_v3_vector"], cve["severity"],
            cve["affected_vendor"], cve["affected_product"], cve["affected_versions"],
            cve["attack_vector"], cve["attack_complexity"],
            cve["privileges_required"], cve["user_interaction"],
            cve["exploit_available"], cve["exploit_description"],
        )
    print(f"  {len(CVES)} CVEs ready")

    # Asset dependencies (web-server depends on app-server, app-server depends on DB)
    print("Seeding asset dependencies…")
    deps = [
        ("web-server-01", "app-server-01",  "api",      True),
        ("app-server-01", "file-server-01", "database", True),
        ("analyst-ws-01", "web-server-01",  "browsing", False),
    ]
    for (up, down, dep_type, is_crit) in deps:
        up_id   = asset_ids.get(up)
        down_id = asset_ids.get(down)
        if up_id and down_id:
            await conn.execute(
                """
                INSERT INTO asset_dependencies
                    (upstream_id, downstream_id, dependency_type, is_critical)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (upstream_id, downstream_id) DO NOTHING
                """,
                up_id, down_id, dep_type, is_crit,
            )
    print(f"  {len(deps)} dependencies seeded")

    print("\nDemo seed complete.")
    print("\nNetwork topology:")
    print("  10.10.1.10  web-server-01   (nginx :80/:443, openssh :22)  — DMZ tier-1")
    print("  10.10.2.10  app-server-01   (tomcat :8080, mysql :3306)    — Internal tier-1")
    print("  10.10.2.20  file-server-01  (smb :445, rdp :3389)          — Internal tier-1")
    print("  10.10.3.100 analyst-ws-01   (openssh :22)                  — Management tier-3")
    print("\nAttacker IPs used by traffic_gen.py:")
    print("  185.220.101.50  — external threat actor")
    print("  203.0.113.99    — external threat actor (secondary)")
    print("  10.10.2.20      — internal lateral movement (file-server acting as pivot)")


async def main():
    print(f"Connecting to {DB_URL}…")
    try:
        conn = await asyncpg.connect(DB_URL)
    except Exception as e:
        print(f"ERROR: Could not connect to database: {e}", file=sys.stderr)
        print("Is PostgreSQL running?  docker-compose up -d postgres", file=sys.stderr)
        sys.exit(1)

    try:
        await seed(conn)
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
