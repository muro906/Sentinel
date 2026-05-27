"""Database operations for plan approvals and rejections."""

import json
import logging
from typing import Optional

from db.connection import get_pool

logger = logging.getLogger(__name__)


async def record_approval(
    alert_id: str,
    plan_id: str,
    approved_by: str,
    actions: list,
    notes: Optional[str] = None,
    modifications: Optional[str] = None,
    decision: str = "approved"
) -> None:
    """Record an approval or rejection decision for a plan.
    
    Inserts into the approvals table and updates the incident status.
    
    Args:
        alert_id: The associated alert identifier.
        plan_id: The plan being approved/rejected.
        approved_by: Username of the analyst making the decision.
        actions: List of approved actions (empty for rejections).
        notes: Optional analyst notes.
        modifications: Optional plan modifications made by analyst.
        decision: Either 'approved' or 'rejected'.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Record the approval/rejection decision
        await conn.execute(
            "INSERT INTO approvals (alert_id,plan_id,decision,approved_by,actions,notes,modifications) "
            "VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)",
            alert_id, plan_id, decision, approved_by, json.dumps(actions), notes, modifications
        )
        # Update incident status
        status = "approved" if decision == "approved" else "rejected"
        await conn.execute(
            "UPDATE incidents SET approval_status=$2,approved_by=$3,approved_at=NOW() WHERE alert_id=$1",
            alert_id, status, approved_by
        )
    logger.info(f"Approval: alert={alert_id} decision={decision} by={approved_by}")