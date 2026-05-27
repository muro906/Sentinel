#!/usr/bin/env python3
"""Database seeding script for testing with dummy data.

Populates the database with sample incidents, assets, CVEs, and test users
matching the frontend mock data structure.
"""

import asyncio
import json
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.connection import init_pool, close_pool, get_pool
from core.security import hash_password

# Sample incidents matching frontend mock data
SAMPLE_INCIDENTS = [
    {
        "alert_id": "a1b2c3d4-0001",
        "classification": "SQL Injection Attempt",
        "priority": "critical",
        "approval_status": "pending",
        "execution_status": "pending",
        "src_ip": "203.0.113.42",
        "dst_ip": "10.0.1.15",
        "dst_port": 5432,
        "anomaly_score": 0.967,
        "plans_generated": json.dumps({
            "plans": [
                {
                    "plan_id": "plan-001",
                    "automation_tier": "automated",
                    "risk_level": "medium",
                    "confidence": 0.94,
                    "rationale": "High-confidence SQL injection attempt against production database. Immediate blocking recommended.",
                    "actions": [
                        {"action_type": "firewall_block", "target": "203.0.113.42", "parameters": {"direction": "inbound"}, "rationale": "Block attacking IP"},
                        {"action_type": "isolate_host", "target": "10.0.1.15", "parameters": {}, "rationale": "Isolate potentially compromised DB"},
                    ],
                },
                {
                    "plan_id": "plan-002",
                    "automation_tier": "manual",
                    "risk_level": "high",
                    "confidence": 0.78,
                    "rationale": "Escalate to DBA team for forensic analysis before isolation.",
                    "actions": [
                        {"action_type": "alert_analyst", "target": "dba-oncall", "parameters": {"priority": "critical"}, "rationale": "Notify DBA team"},
                        {"action_type": "deep_inspect", "target": "10.0.1.15", "parameters": {"duration": 3600}, "rationale": "Capture packets for forensics"},
                    ],
                },
            ]
        }),
    },
    {
        "alert_id": "a1b2c3d4-0002",
        "classification": "Lateral Movement Detected",
        "priority": "high",
        "approval_status": "pending",
        "execution_status": "pending",
        "src_ip": "10.0.2.88",
        "dst_ip": "10.0.1.20",
        "dst_port": 445,
        "anomaly_score": 0.812,
        "plans_generated": json.dumps({
            "plans": [
                {
                    "plan_id": "plan-003",
                    "automation_tier": "semi-automated",
                    "risk_level": "high",
                    "confidence": 0.91,
                    "rationale": "SMB traffic from workstation to app server suggests lateral movement.",
                    "actions": [
                        {"action_type": "firewall_block", "target": "10.0.2.88", "parameters": {"direction": "outbound", "port": 445}, "rationale": "Block SMB from compromised workstation"},
                        {"action_type": "isolate_host", "target": "10.0.2.88", "parameters": {}, "rationale": "Isolate compromised workstation"},
                    ],
                },
            ]
        }),
    },
    {
        "alert_id": "a1b2c3d4-0003",
        "classification": "Brute Force SSH Login",
        "priority": "medium",
        "approval_status": "approved",
        "execution_status": "executed",
        "src_ip": "198.51.100.77",
        "dst_ip": "10.0.0.5",
        "dst_port": 22,
        "anomaly_score": 0.654,
        "plans_generated": json.dumps({
            "plans": [
                {
                    "plan_id": "plan-005",
                    "automation_tier": "automated",
                    "risk_level": "medium",
                    "confidence": 0.87,
                    "rationale": "Brute force detected on bastion host. Block source IP and enforce MFA immediately.",
                    "actions": [
                        {"action_type": "firewall_block", "target": "198.51.100.77", "parameters": {"direction": "inbound", "ttl": 86400}, "rationale": "Block attacking IP for 24 hours"},
                    ],
                },
            ]
        }),
    },
]

# Sample assets
SAMPLE_ASSETS = [
    {"id": 1, "hostname": "db-prod-01", "ip_address": "10.0.1.15", "os": "Ubuntu 22.04", "asset_type": "database", "criticality_tier": 1, "is_active": True, "zone_id": 1},
    {"id": 2, "hostname": "app-server-03", "ip_address": "10.0.1.20", "os": "RHEL 9", "asset_type": "application", "criticality_tier": 2, "is_active": True, "zone_id": 2},
    {"id": 3, "hostname": "bastion-01", "ip_address": "10.0.0.5", "os": "Ubuntu 22.04", "asset_type": "bastion", "criticality_tier": 1, "is_active": True, "zone_id": 3},
    {"id": 4, "hostname": "workstation-12", "ip_address": "10.0.2.88", "os": "Windows 11", "asset_type": "workstation", "criticality_tier": 3, "is_active": True, "zone_id": 4},
]

# Sample network zones
SAMPLE_ZONES = [
    {"id": 1, "zone_name": "data", "trust_level": "high"},
    {"id": 2, "zone_name": "app", "trust_level": "medium"},
    {"id": 3, "zone_name": "dmz", "trust_level": "low"},
    {"id": 4, "zone_name": "user", "trust_level": "low"},
]

# Sample CVEs
SAMPLE_CVE_ENTRIES = [
    {"cve_id": "CVE-2023-34362", "cvss_v3_score": 9.8, "severity": "CRITICAL", "affected_vendor": "Progress", "affected_product": "MOVEit Transfer", "attack_vector": "NETWORK", "exploit_available": True, "description": "SQL injection vulnerability in MOVEit Transfer web application."},
    {"cve_id": "CVE-2021-44228", "cvss_v3_score": 10.0, "severity": "CRITICAL", "affected_vendor": "Apache", "affected_product": "Apache Log4j", "attack_vector": "NETWORK", "exploit_available": True, "description": "Remote code execution vulnerability in Apache Log4j2 JNDI features."},
    {"cve_id": "CVE-2017-0144", "cvss_v3_score": 8.1, "severity": "HIGH", "affected_vendor": "Microsoft", "affected_product": "Microsoft SMBv1", "attack_vector": "NETWORK", "exploit_available": True, "description": "The SMBv1 server allows remote attackers to execute arbitrary code."},
    {"cve_id": "CVE-2022-22965", "cvss_v3_score": 9.8, "severity": "CRITICAL", "affected_vendor": "Spring", "affected_product": "Spring Framework", "attack_vector": "NETWORK", "exploit_available": True, "description": "Spring4Shell: RCE vulnerability in Spring MVC."},
]

# Sample reasoning traces
SAMPLE_TRACES = [
    {"event_id": "ev-001", "alert_id": "a1b2c3d4-0001", "event_type": "alert_received", "agent_name": "orchestrator", "action": "ingest", "rationale": "New critical alert ingested from SIEM", "confidence": None, "duration_ms": 12},
    {"event_id": "ev-002", "alert_id": "a1b2c3d4-0001", "event_type": "cve_search", "agent_name": "cve_lookup", "action": "search", "rationale": "Searching CVE database for SQL injection signatures", "confidence": 0.95, "duration_ms": 340},
    {"event_id": "ev-003", "alert_id": "a1b2c3d4-0001", "event_type": "asset_resolve", "agent_name": "asset_discovery", "action": "resolve", "rationale": "Resolved 10.0.1.15 to db-prod-01 (Tier 1, data zone)", "confidence": 0.88, "duration_ms": 210},
    {"event_id": "ev-004", "alert_id": "a1b2c3d4-0001", "event_type": "plan_generation", "agent_name": "planning", "action": "generate", "rationale": "Generating 2 remediation plans based on CVE context", "confidence": 0.89, "duration_ms": 1240},
]

# Test users - keep passwords under 72 bytes for bcrypt
TEST_USERS = [
    {"username": "admin", "password": "admin123", "role": "admin", "is_active": True},
    {"username": "analyst", "password": "analyst123", "role": "analyst", "is_active": True},
    {"username": "senior", "password": "senior123", "role": "senior_analyst", "is_active": True},
]


async def seed_database():
    """Populate database with sample test data."""
    await init_pool()
    pool = await get_pool()
    
    async with pool.acquire() as conn:
        # Clear existing data (optional - comment out if you want to preserve)
        await conn.execute("TRUNCATE TABLE reasoning_traces, approvals, incidents, services, assets, network_zones, users, cve_entries RESTART IDENTITY CASCADE")
        
        # Insert network zones
        for zone in SAMPLE_ZONES:
            await conn.execute(
                "INSERT INTO network_zones (id, zone_name, trust_level) VALUES ($1, $2, $3)",
                zone["id"], zone["zone_name"], zone["trust_level"]
            )
        print(f"Inserted {len(SAMPLE_ZONES)} network zones")
        
        # Insert assets
        for asset in SAMPLE_ASSETS:
            await conn.execute(
                """INSERT INTO assets (id, hostname, ip_address, os, asset_type, criticality_tier, is_active, zone_id)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                asset["id"], asset["hostname"], asset["ip_address"], asset["os"],
                asset["asset_type"], asset["criticality_tier"], asset["is_active"], asset["zone_id"]
            )
        print(f"Inserted {len(SAMPLE_ASSETS)} assets")
        
        # Insert incidents
        for inc in SAMPLE_INCIDENTS:
            await conn.execute(
                """INSERT INTO incidents (alert_id, classification, priority, approval_status, execution_status,
                    src_ip, dst_ip, dst_port, anomaly_score, plans_generated, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, NOW())""",
                inc["alert_id"], inc["classification"], inc["priority"], inc["approval_status"],
                inc["execution_status"], inc["src_ip"], inc["dst_ip"], inc["dst_port"],
                inc["anomaly_score"], inc["plans_generated"]
            )
        print(f"Inserted {len(SAMPLE_INCIDENTS)} incidents")
        
        # Insert CVE entries
        for cve in SAMPLE_CVE_ENTRIES:
            await conn.execute(
                """INSERT INTO cve_entries (cve_id, cvss_v3_score, severity, affected_vendor,
                    affected_product, attack_vector, exploit_available, description)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                cve["cve_id"], cve["cvss_v3_score"], cve["severity"], cve["affected_vendor"],
                cve["affected_product"], cve["attack_vector"], cve["exploit_available"], cve["description"]
            )
        print(f"Inserted {len(SAMPLE_CVE_ENTRIES)} CVE entries")
        
        # Insert reasoning traces
        for trace in SAMPLE_TRACES:
            await conn.execute(
                """INSERT INTO reasoning_traces (event_id, alert_id, event_type, agent_name, action,
                    rationale, confidence, duration_ms, timestamp)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())""",
                trace["event_id"], trace["alert_id"], trace["event_type"], trace["agent_name"],
                trace["action"], trace["rationale"], trace["confidence"], trace["duration_ms"]
            )
        print(f"Inserted {len(SAMPLE_TRACES)} reasoning traces")
        
        # Insert test users
        for user in TEST_USERS:
            hashed_pw = hash_password(user["password"])
            await conn.execute(
                "INSERT INTO users (username, hashed_password, role, is_active) VALUES ($1, $2, $3, $4)",
                user["username"], hashed_pw, user["role"], user["is_active"]
            )
        print(f"Inserted {len(TEST_USERS)} test users")
        
        # Insert sample services for assets
        services = [
            {"asset_id": 1, "port": 5432, "protocol": "tcp", "service_name": "postgresql", "version": "14.5", "is_exposed": False},
            {"asset_id": 2, "port": 80, "protocol": "tcp", "service_name": "nginx", "version": "1.22", "is_exposed": True},
            {"asset_id": 2, "port": 443, "protocol": "tcp", "service_name": "nginx", "version": "1.22", "is_exposed": True},
            {"asset_id": 3, "port": 22, "protocol": "tcp", "service_name": "ssh", "version": "8.9", "is_exposed": True},
        ]
        for svc in services:
            await conn.execute(
                """INSERT INTO services (asset_id, port, protocol, service_name, version, is_exposed)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                svc["asset_id"], svc["port"], svc["protocol"], svc["service_name"], svc["version"], svc["is_exposed"]
            )
        print(f"Inserted {len(services)} services")
    
    print("\nDatabase seeding complete!")
    print("Test users:")
    for user in TEST_USERS:
        print(f"  - {user['username']} / {user['password']} (role: {user['role']})")
    
    await close_pool()


if __name__ == "__main__":
    asyncio.run(seed_database())
