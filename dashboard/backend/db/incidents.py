"""Database operations for security incidents and alerts."""

import json
import logging
from typing import Optional

from db.connection import get_pool

logger = logging.getLogger(__name__)


async def list_incidents(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    assigned_to: Optional[str] = None,
) -> dict:
    """List security incidents with optional filtering and pagination.
    
    Results are ordered by priority (critical first) then creation time.
    
    Args:
        status: Optional filter by approval status.
        priority: Optional filter by priority level.
        page: Page number (1-indexed).
        limit: Maximum items per page.
        assigned_to: Optional filter by assigned analyst username.
        
    Returns:
        Dictionary with paginated incident list, total count, and pagination info.
    """
    pool = await get_pool()
    offset = (page - 1) * limit
    conds, params, i = [], [], 1
    if status:
        conds.append(f"approval_status=${i}")
        params.append(status)
        i += 1
    if priority:
        conds.append(f"priority=${i}")
        params.append(priority)
        i += 1
    if assigned_to:
        conds.append(f"assigned_to=${i}")
        params.append(assigned_to)
        i += 1
    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    # Priority ordering: critical > high > medium > low
    pord = "CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END"
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT alert_id,classification,anomaly_score,src_ip::text,dst_ip::text,"
            f"dst_port,priority,approval_status,execution_status,assigned_to,"
            f"approved_by,approved_at,created_at "
            f"FROM incidents {where} ORDER BY {pord},created_at DESC LIMIT ${i} OFFSET ${i+1}",
            *params, limit, offset
        )
        total = await conn.fetchval(f"SELECT COUNT(*) FROM incidents {where}", *params)
    items = []
    for r in rows:
        d = dict(r)
        for ts_field in ("created_at", "approved_at"):
            if d.get(ts_field):
                d[ts_field] = d[ts_field].isoformat()
        items.append(d)
    return {"items": items, "total": total, "page": page, "limit": limit}



async def get_incident(alert_id: str) -> Optional[dict]:
    """Get detailed information about a specific incident.
    
    Args:
        alert_id: The unique alert identifier.
        
    Returns:
        Complete incident record with formatted timestamps and IP addresses,
        or None if not found.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM incidents WHERE alert_id=$1", alert_id)
    if not row:
        return None
    r = dict(row)
    # Convert datetime objects to ISO format strings
    for f in ("created_at", "triaged_at", "plans_ready_at", "approved_at", "executed_at", "closed_at"):
        if r.get(f):
            r[f] = r[f].isoformat()
    # Convert IP address objects to strings
    for f in ("src_ip", "dst_ip"):
        if r.get(f):
            r[f] = str(r[f])
    # asyncpg returns JSONB columns as raw strings — parse them to Python objects
    for f in ("plans_generated", "cve_matches", "affected_assets"):
        v = r.get(f)
        if v is None:
            continue
        if isinstance(v, str):
            try:
                r[f] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                r[f] = [] if f != "plans_generated" else {}
        # cve_matches and affected_assets must always be lists
        if f in ("cve_matches", "affected_assets") and not isinstance(r[f], list):
            r[f] = []
    return r


async def upsert_plan_set(alert_id: str, plan_set: dict) -> None:
    """Store generated execution plans for an incident.
    
    Updates the incident record with the plan set JSON and sets status to 'pending'.
    
    Args:
        alert_id: The incident identifier.
        plan_set: Dictionary containing the generated execution plans.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE incidents SET plans_generated=$2::jsonb, approval_status='plans_generated', plans_ready_at=NOW() WHERE alert_id=$1",
            alert_id, json.dumps(plan_set)
        )