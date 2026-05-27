"""Alert/incident listing and retrieval router."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.dependencies import analyst_or_above, get_current_user, CurrentUser
from core.email import email_service
from db.connection import get_pool
from db.incidents import get_incident, list_incidents
from ws.manager import manager

router = APIRouter()

# Priority hierarchy — used for self-assignment cap enforcement
PRIORITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# Analysts can only self-assign up to medium priority
ANALYST_SELF_ASSIGN_MAX_PRIORITY = "medium"


class AssignRequest(BaseModel):
    analyst_id: Optional[str] = None


@router.get("")
async def list_alerts(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, le=200),
    _: None = Depends(analyst_or_above)
) -> dict:
    """List security incidents/alerts with optional filtering.
    
    Args:
        status: Filter by approval status (pending, approved, rejected).
        priority: Filter by priority level (critical, high, medium, low).
        page: Page number for pagination.
        limit: Items per page (max 200).
        _: Authentication dependency (unused).
        
    Returns:
        Paginated list of incidents.
    """
    return await list_incidents(status=status, priority=priority, page=page, limit=limit)


@router.get("/my")
async def get_my_alerts(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, le=200),
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    """List alerts assigned to the current user.

    Args:
        status: Optional filter by approval status.
        priority: Optional filter by priority level.
        page: Page number for pagination.
        limit: Items per page (max 200).
        user: Current authenticated user.

    Returns:
        Paginated list of incidents assigned to the current user.
    """
    return await list_incidents(
        status=status,
        priority=priority,
        page=page,
        limit=limit,
        assigned_to=user.username
    )


@router.get("/{alert_id}")
async def get_alert(alert_id: str, _: None = Depends(analyst_or_above)) -> dict:
    """Get detailed information about a specific alert."""
    inc = await get_incident(alert_id)
    if not inc:
        raise HTTPException(404, "Alert not found")
    return inc


@router.get("/{alert_id}/approval")
async def get_alert_approval(alert_id: str, _: None = Depends(analyst_or_above)) -> dict:
    """Get the approval/rejection record for a resolved alert."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT a.id, a.alert_id, a.plan_id, a.decision, a.approved_by,
                      a.actions, a.notes, a.modifications, a.created_at
               FROM approvals a
               WHERE a.alert_id = $1
               ORDER BY a.created_at DESC
               LIMIT 1""",
            alert_id
        )
    if not row:
        raise HTTPException(404, "No approval record found for this alert")

    d = dict(row)
    if d.get("created_at"):
        d["created_at"] = d["created_at"].isoformat()
    if isinstance(d.get("actions"), str):
        import json as _json
        try:
            d["actions"] = _json.loads(d["actions"])
        except Exception:
            d["actions"] = []
    return d


@router.post("/{alert_id}/assign")
async def assign_alert(
    alert_id: str,
    body: AssignRequest,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above)
) -> dict:
    """Assign an alert to an analyst.

    Self-assignment by regular analysts is capped at medium priority.
    Senior analysts and admins can self-assign any priority.

    Args:
        alert_id: The alert identifier.
        body: Assignment request with analyst_id.
        user: Current user making the assignment.
        _: Role verification.

    Raises:
        HTTPException: 403 if analyst tries to self-assign a high/critical alert.
        HTTPException: 404 if alert not found.

    Returns:
        Confirmation with alert_id and assigned_to.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Get alert details and current assignment
        alert = await conn.fetchrow(
            "SELECT classification, priority, assigned_to FROM incidents WHERE alert_id = $1",
            alert_id
        )
        if not alert:
            raise HTTPException(404, "Alert not found")

        # ── Self-assignment priority cap ──────────────────────────────────────
        is_self_assign = body.analyst_id == user.username
        if is_self_assign and user.role == "analyst":
            alert_priority = (alert["priority"] or "low").lower()
            max_priority = ANALYST_SELF_ASSIGN_MAX_PRIORITY
            if PRIORITY_ORDER.get(alert_priority, 0) > PRIORITY_ORDER.get(max_priority, 0):
                raise HTTPException(
                    403,
                    f"Analysts can only self-assign alerts up to '{max_priority}' priority. "
                    f"This alert is '{alert_priority}'. Please ask a Senior Analyst or Admin to assign it."
                )

        # ── Block self-assign when alert is already taken ─────────────────────
        if is_self_assign and alert["assigned_to"] and alert["assigned_to"] != user.username:
            if user.role not in ("admin", "senior_analyst"):
                raise HTTPException(
                    409,
                    f"This alert is already assigned to '{alert['assigned_to']}'. "
                    f"You cannot self-assign it while it is taken."
                )

        previous_assignee = alert["assigned_to"]

        # Update assignment
        await conn.execute(
            "UPDATE incidents SET assigned_to = $1 WHERE alert_id = $2",
            body.analyst_id, alert_id
        )

        # Get target user details if assigning
        target_user = None
        if body.analyst_id:
            target_user = await conn.fetchrow(
                "SELECT username, email FROM users WHERE username = $1 AND is_active = TRUE",
                body.analyst_id
            )

    # Send notifications
    is_assigned = body.analyst_id is not None

    # 1. WebSocket notification to feed channel (for dashboard updates)
    await manager.broadcast("feed", {
        "type": "alert_assigned" if is_assigned else "alert_unassigned",
        "alert_id": alert_id,
        "alert_classification": alert["classification"],
        "alert_priority": alert["priority"],
        "assigned_to": body.analyst_id,
        "assigned_by": user.username,
        "previous_assignee": previous_assignee
    })

    # 2. Email notification to assigned user (skip for self-assignments — they know)
    if target_user and target_user["email"] and not is_self_assign:
        await email_service.send_alert_assignment_notification(
            to_email=target_user["email"],
            username=target_user["username"],
            alert_id=alert_id,
            alert_classification=alert["classification"],
            alert_priority=alert["priority"],
            assigned_by=user.username,
            is_assigned=True
        )

    # 3. Email notification to previous assignee (if unassigned)
    if previous_assignee and previous_assignee != body.analyst_id:
        async with pool.acquire() as conn:
            prev_user = await conn.fetchrow(
                "SELECT email FROM users WHERE username = $1",
                previous_assignee
            )
        if prev_user and prev_user["email"]:
            await email_service.send_alert_assignment_notification(
                to_email=prev_user["email"],
                username=previous_assignee,
                alert_id=alert_id,
                alert_classification=alert["classification"],
                alert_priority=alert["priority"],
                assigned_by=user.username,
                is_assigned=False
            )

    return {
        "alert_id": alert_id,
        "assigned_to": body.analyst_id,
        "email_sent": target_user is not None and target_user.get("email") is not None
    }