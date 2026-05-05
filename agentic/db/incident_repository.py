"""
Incident Repository
====================
Database access layer for incident lifecycle management:
- Creating incident records when alerts are processed
- Updating incidents with plans, approvals, and execution results
- Querying historical incidents for LLM few-shot context
- Closing incidents with outcome summaries
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from .connection import get_pool

logger = logging.getLogger(__name__)


async def create_incident(
    alert_id: str,
    classification: str,
    anomaly_score: float,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    priority: str,
    feature_vector: dict,
) -> Optional[int]:
    """
    Create a new incident record when an alert begins processing.
    Returns the incident row ID.
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO incidents
                (alert_id, classification, anomaly_score, src_ip, dst_ip, dst_port,
                 priority, feature_vector, status, received_at)
            VALUES ($1, $2, $3, $4::inet, $5::inet, $6, $7, $8::jsonb, 'received', NOW())
            ON CONFLICT (alert_id) DO UPDATE SET
                status = 'received',
                received_at = NOW()
            RETURNING id
        """, alert_id, classification, anomaly_score, src_ip, dst_ip, dst_port,
             priority, json.dumps(feature_vector))

    if row:
        logger.debug(f"Created incident {row['id']} for alert {alert_id}")
        return row["id"]
    return None


async def update_incident_plans(alert_id: str, plans: list[dict], cve_matches: list[dict]):
    """Store generated plans and CVE matches on the incident."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE incidents SET
                plans_generated = $2::jsonb,
                cve_matches = $3::jsonb,
                status = 'plans_generated',
                plans_generated_at = NOW()
            WHERE alert_id = $1
        """, alert_id, json.dumps(plans), json.dumps(cve_matches))


async def update_incident_approval(
    alert_id: str,
    approved_plan_id: str,
    approved_by: str,
    approved_actions: list[dict],
):
    """Record plan approval on the incident."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE incidents SET
                approved_plan_id = $2,
                approved_by = $3,
                approved_actions = $4::jsonb,
                status = 'approved',
                approved_at = NOW()
            WHERE alert_id = $1
        """, alert_id, approved_plan_id, approved_by, json.dumps(approved_actions))


async def update_incident_execution(
    alert_id: str,
    execution_results: list[dict],
    status: str = "executed",
):
    """Record execution results on the incident."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE incidents SET
                execution_results = $2::jsonb,
                status = $3,
                executed_at = NOW()
            WHERE alert_id = $1
        """, alert_id, json.dumps(execution_results), status)


async def close_incident(alert_id: str, outcome: str, analyst_notes: Optional[str] = None):
    """Close an incident with final outcome."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE incidents SET
                status = 'closed',
                outcome = $2,
                analyst_notes = $3,
                closed_at = NOW()
            WHERE alert_id = $1
        """, alert_id, outcome, analyst_notes)


async def find_similar_incidents(
    classification: str,
    dst_port: Optional[int] = None,
    limit: int = 5,
    max_age_days: int = 90,
) -> list[dict]:
    """
    Find historical incidents with the same classification and optional
    port match. Used to provide few-shot context to the LLM.

    Returns incidents ordered by recency, including their plans and outcomes.
    """
    pool = await get_pool()
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    if dst_port:
        sql = """
            SELECT alert_id, classification, anomaly_score, src_ip, dst_ip, dst_port,
                   priority, status, outcome, plans_generated, approved_plan_id,
                   execution_results, received_at
            FROM incidents
            WHERE classification = $1
              AND dst_port = $2
              AND status = 'closed'
              AND received_at >= $3
            ORDER BY received_at DESC
            LIMIT $4
        """
        params = [classification, dst_port, cutoff, limit]
    else:
        sql = """
            SELECT alert_id, classification, anomaly_score, src_ip, dst_ip, dst_port,
                   priority, status, outcome, plans_generated, approved_plan_id,
                   execution_results, received_at
            FROM incidents
            WHERE classification = $1
              AND status = 'closed'
              AND received_at >= $2
            ORDER BY received_at DESC
            LIMIT $3
        """
        params = [classification, cutoff, limit]

    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)

    results = []
    for row in rows:
        record = dict(row)
        # Convert datetimes to ISO strings
        if record.get("received_at"):
            record["received_at"] = record["received_at"].isoformat()
        results.append(record)

    return results


async def get_incident(alert_id: str) -> Optional[dict]:
    """Fetch a single incident by alert_id."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM incidents WHERE alert_id = $1", alert_id
        )

    return dict(row) if row else None


async def list_active_incidents(limit: int = 50) -> list[dict]:
    """List all non-closed incidents, ordered by priority then recency."""
    pool = await get_pool()

    priority_order = "CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END"

    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT alert_id, classification, anomaly_score, src_ip, dst_ip, dst_port,
                   priority, status, received_at
            FROM incidents
            WHERE status != 'closed'
            ORDER BY {priority_order}, received_at DESC
            LIMIT $1
        """, limit)

    return [dict(row) for row in rows]
