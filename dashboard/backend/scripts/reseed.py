#!/usr/bin/env python3
"""
Reseed script — guarantees every alert has at least one plan and a full reasoning trace.
Run: python3 scripts/reseed.py
"""
import asyncio, json, os, sys, uuid
from datetime import datetime, timedelta, timezone
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.connection import init_pool, close_pool, get_pool

random.seed(99)

NOW = datetime.utcnow()          # naive UTC — matches DB TIMESTAMP WITHOUT TIME ZONE

def ago(**kw):
    return NOW - timedelta(**kw)

# ── Alert definitions ─────────────────────────────────────────────────────────
INCIDENTS = [
    # Active — analysts working these
    dict(
        alert_id="inc-sql-001", classification="SQL Injection Attempt",
        priority="critical", approval_status="plans_generated",
        src_ip="203.0.113.42", dst_ip="10.0.1.15", dst_port=5432,
        anomaly_score=0.967, assigned_to="analyst", created_at=ago(hours=2),
    ),
    dict(
        alert_id="inc-lat-002", classification="Lateral Movement via SMB",
        priority="high", approval_status="triaged",
        src_ip="10.0.2.88", dst_ip="10.0.1.20", dst_port=445,
        anomaly_score=0.812, assigned_to="senior", created_at=ago(hours=5),
    ),
    dict(
        alert_id="inc-rdp-003", classification="Brute Force RDP Login",
        priority="high", approval_status="plans_generated",
        src_ip="185.220.101.55", dst_ip="10.0.3.10", dst_port=3389,
        anomaly_score=0.891, assigned_to=None, created_at=ago(hours=1),
    ),
    dict(
        alert_id="inc-dns-004", classification="DNS Exfiltration Pattern",
        priority="medium", approval_status="pending",
        src_ip="10.0.2.55", dst_ip="8.8.8.8", dst_port=53,
        anomaly_score=0.743, assigned_to="analyst", created_at=ago(hours=3),
    ),
    dict(
        alert_id="inc-c2-005", classification="C2 Beacon Detected",
        priority="critical", approval_status="plans_generated",
        src_ip="10.0.1.99", dst_ip="45.33.32.156", dst_port=4444,
        anomaly_score=0.988, assigned_to="senior", created_at=ago(minutes=45),
    ),
    dict(
        alert_id="inc-priv-006", classification="Privilege Escalation Attempt",
        priority="high", approval_status="triaged",
        src_ip="10.0.2.77", dst_ip="10.0.1.5", dst_port=22,
        anomaly_score=0.856, assigned_to=None, created_at=ago(hours=4),
    ),
    dict(
        alert_id="inc-scan-007", classification="Port Scan Detected",
        priority="low", approval_status="received",
        src_ip="192.168.1.200", dst_ip="10.0.0.0", dst_port=0,
        anomaly_score=0.412, assigned_to=None, created_at=ago(minutes=20),
    ),
    dict(
        alert_id="inc-mal-008", classification="Malware Dropper Execution",
        priority="critical", approval_status="pending",
        src_ip="10.0.3.22", dst_ip="91.121.89.70", dst_port=80,
        anomaly_score=0.979, assigned_to="analyst", created_at=ago(hours=1, minutes=30),
    ),
    dict(
        alert_id="inc-phi-009", classification="Phishing Link Clicked",
        priority="medium", approval_status="plans_generated",
        src_ip="10.0.4.11", dst_ip="52.14.88.201", dst_port=443,
        anomaly_score=0.694, assigned_to="analyst", created_at=ago(hours=6),
    ),
    dict(
        alert_id="inc-tor-010", classification="Tor Exit Node Traffic",
        priority="high", approval_status="triaged",
        src_ip="10.0.5.33", dst_ip="185.220.100.255", dst_port=9001,
        anomaly_score=0.877, assigned_to="senior", created_at=ago(hours=2, minutes=30),
    ),
    # History — already resolved
    dict(
        alert_id="inc-ssh-h01", classification="Brute Force SSH Login",
        priority="medium", approval_status="approved",
        src_ip="198.51.100.77", dst_ip="10.0.0.5", dst_port=22,
        anomaly_score=0.654, assigned_to="senior",
        approved_by="senior", approved_at=ago(hours=24), created_at=ago(hours=26),
    ),
    dict(
        alert_id="inc-xss-h02", classification="Reflected XSS Attack",
        priority="medium", approval_status="rejected",
        src_ip="203.0.113.100", dst_ip="10.0.1.80", dst_port=443,
        anomaly_score=0.523, assigned_to="analyst",
        approved_by="admin", approved_at=ago(hours=48), created_at=ago(hours=50),
    ),
    dict(
        alert_id="inc-rce-h03", classification="Log4Shell RCE Attempt",
        priority="critical", approval_status="executed",
        src_ip="45.141.84.120", dst_ip="10.0.1.30", dst_port=8080,
        anomaly_score=0.997, assigned_to="admin",
        approved_by="admin", approved_at=ago(hours=72), created_at=ago(hours=74),
    ),
    dict(
        alert_id="inc-exf-h04", classification="Data Exfiltration via HTTPS",
        priority="high", approval_status="closed",
        src_ip="10.0.2.45", dst_ip="104.21.14.55", dst_port=443,
        anomaly_score=0.801, assigned_to="senior",
        approved_by="senior", approved_at=ago(hours=120), created_at=ago(hours=122),
    ),
    dict(
        alert_id="inc-ran-h05", classification="Ransomware Staging Detected",
        priority="critical", approval_status="executed",
        src_ip="10.0.3.88", dst_ip="10.0.1.10", dst_port=445,
        anomaly_score=0.994, assigned_to="admin",
        approved_by="admin", approved_at=ago(hours=96), created_at=ago(hours=98),
    ),
]

# ── Plan templates per classification keyword ─────────────────────────────────
def make_plans(inc):
    cls = inc["classification"].lower()
    pri = inc["priority"]
    src = inc["src_ip"]
    dst = inc["dst_ip"]

    plan1_id = f"plan-{uuid.uuid4().hex[:8]}"
    plan2_id = f"plan-{uuid.uuid4().hex[:8]}"

    # Primary plan — always aggressive
    actions1 = [
        {"action_type": "firewall_block", "target": src,
         "parameters": {"direction": "inbound", "ttl": 86400},
         "rationale": f"Block attacking IP {src} for 24h"},
        {"action_type": "notify",         "target": "soc-team",
         "parameters": {"channel": "slack", "priority": pri},
         "rationale": "Alert SOC channel of automated block"},
    ]
    if pri in ("critical", "high"):
        actions1.append({
            "action_type": "isolate_host", "target": dst,
            "parameters": {}, "rationale": f"Isolate potentially compromised host {dst}",
        })

    # Conservative plan
    actions2 = [
        {"action_type": "deep_inspect", "target": dst,
         "parameters": {"duration": 3600}, "rationale": "Capture packets for forensic analysis"},
        {"action_type": "rate_limit",   "target": src,
         "parameters": {"rate": "5/min"}, "rationale": "Throttle without full block"},
    ]
    if "credential" in cls or "priv" in cls:
        actions2.append({
            "action_type": "credential_rotate", "target": dst,
            "parameters": {"scope": "local"}, "rationale": "Rotate credentials on affected host",
        })

    plans = [
        {
            "plan_id": plan1_id,
            "automation_tier": "L3" if pri in ("critical","high") else "L1",
            "risk_level": "high" if pri in ("critical","high") else "low",
            "confidence": round(random.uniform(0.85, 0.97), 2),
            "description": f"Aggressive automated response for {inc['classification']}.",
            "estimated_duration_seconds": random.randint(30, 90),
            "actions": actions1,
        },
        {
            "plan_id": plan2_id,
            "automation_tier": "L2",
            "risk_level": "medium",
            "confidence": round(random.uniform(0.70, 0.84), 2),
            "description": f"Conservative observe-and-contain approach for {inc['classification']}.",
            "estimated_duration_seconds": random.randint(120, 480),
            "actions": actions2,
        },
    ]
    return json.dumps({"plans": plans}), plan1_id, actions1


# ── Trace chain templates ─────────────────────────────────────────────────────
TRACE_STEPS = [
    ("orchestrator",     "ingest",         "alert_received",  "New {priority} alert ingested: {cls}",                    None, 12),
    ("cve_lookup",       "search",         "cve_search",      "Searching CVE DB for signatures matching {cls}",           0.95, 340),
    ("asset_discovery",  "resolve",        "asset_resolve",   "Resolved {dst} — hostname and criticality tier mapped",    0.88, 210),
    ("threat_intel",     "enrich",         "threat_enrich",   "Querying threat feeds for src IP {src}",                   0.91, 450),
    ("risk_scorer",      "score",          "risk_assessment", "Computed risk score: priority={priority}, asset=Tier-1",   0.93, 180),
    ("planning",         "generate",       "plan_generation", "Generated 2 remediation plans based on enriched context",  0.89, 1240),
    ("planning",         "rank",           "plan_ranking",    "Ranked plans by confidence; aggressive plan selected #1",  0.87, 320),
    ("orchestrator",     "await_approval", "pending_approval","Plans ready — awaiting analyst approval before execution",  None, 5),
]


async def seed():
    await init_pool()
    pool = await get_pool()

    async with pool.acquire() as conn:
        print("Truncating incidents, traces, approvals, escalations, transfers …")
        await conn.execute(
            "TRUNCATE TABLE reasoning_traces, approvals, plan_escalations,"
            " alert_transfer_requests, incidents RESTART IDENTITY CASCADE"
        )

        for inc in INCIDENTS:
            plans_json, first_plan_id, first_plan_actions = make_plans(inc)

            # ── Incident ──────────────────────────────────────────────────────
            await conn.execute(
                """INSERT INTO incidents
                   (alert_id, classification, priority, approval_status, execution_status,
                    src_ip, dst_ip, dst_port, anomaly_score, plans_generated,
                    assigned_to, approved_by, approved_at, created_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14)""",
                inc["alert_id"], inc["classification"], inc["priority"],
                inc["approval_status"],
                "executed" if inc["approval_status"] in ("approved","executed","closed") else "pending",
                inc["src_ip"], inc["dst_ip"], inc.get("dst_port"),
                inc["anomaly_score"], plans_json,
                inc.get("assigned_to"),
                inc.get("approved_by"),
                inc.get("approved_at"),
                inc.get("created_at", NOW),
            )

            # ── Approval record for history items ─────────────────────────────
            if inc.get("approved_by"):
                is_approved = inc["approval_status"] in ("approved","executed","closed")
                await conn.execute(
                    """INSERT INTO approvals
                       (alert_id, plan_id, decision, approved_by, actions, notes, created_at)
                       VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)""",
                    inc["alert_id"], first_plan_id,
                    "approved" if is_approved else "rejected",
                    inc["approved_by"],
                    json.dumps(first_plan_actions if is_approved else []),
                    ("Automated block applied. Source confirmed malicious via threat intel feed."
                     if is_approved else
                     "False positive — internal scanner registered as external. No action required."),
                    inc.get("approved_at", NOW),
                )

            # ── Reasoning traces (all 8 steps for every alert) ────────────────
            t = inc.get("created_at", NOW)
            for i, (agent, action, etype, tpl, conf, dur) in enumerate(TRACE_STEPS):
                rationale = tpl.format(
                    cls=inc["classification"],
                    priority=inc["priority"],
                    src=inc["src_ip"],
                    dst=inc["dst_ip"],
                )
                t = t + timedelta(seconds=random.randint(8, 60))
                await conn.execute(
                    """INSERT INTO reasoning_traces
                       (event_id, alert_id, event_type, agent_name, action,
                        rationale, confidence, duration_ms, timestamp)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)""",
                    f"ev-{inc['alert_id']}-{i:02d}",
                    inc["alert_id"], etype, agent, action,
                    rationale, conf, dur, t,
                )

        row = await conn.fetchrow(
            "SELECT (SELECT COUNT(*) FROM incidents)       AS alerts,"
            "       (SELECT COUNT(*) FROM reasoning_traces) AS traces,"
            "       (SELECT COUNT(*) FROM approvals)        AS approvals"
        )

    await close_pool()

    print(f"✓ {row['alerts']} alerts  |  {row['traces']} traces  |  {row['approvals']} approvals")
    active  = sum(1 for i in INCIDENTS if not i.get("approved_by"))
    history = sum(1 for i in INCIDENTS if i.get("approved_by"))
    print(f"  Active: {active}   History: {history}")
    print("\nCredentials: admin/admin123 · senior/admin123 · analyst/analyst123")


if __name__ == "__main__":
    asyncio.run(seed())
