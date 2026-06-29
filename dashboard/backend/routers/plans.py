"""Plan management router for retrieving and approving remediation plans."""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.dependencies import admin_only, analyst_or_above, get_current_user, CurrentUser, senior_or_above
from core.email import email_service
from db.approvals import record_approval
from db.connection import get_pool
from db.incidents import get_incident
from kafka.producer import publish_approval
from models.plans import ApprovalRequest
from ws.manager import manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Whitelist of allowed remediation action types
ALLOWED = {
    "firewall_block", "firewall_unblock", "isolate_host", "restore_host",
    "patch", "notify", "deep_inspect", "rate_limit", "credential_rotate"
}

# Destructive actions that require admin or senior approval
DESTRUCTIVE_ACTIONS = {
    "firewall_block", "firewall_unblock", "isolate_host", "restore_host", 
    "credential_rotate"
}


class EscalationRequest(BaseModel):
    """Request to escalate plan approval to admin/senior."""
    plan_id: str
    reason: str
    actions: List[dict]


@router.get("/{alert_id}/plans")
async def get_plans(
    alert_id: str, 
    user: CurrentUser = Depends(get_current_user)
) -> dict:
    """Retrieve generated execution plans for an alert.
    
    Args:
        alert_id: The alert identifier.
        user: Current authenticated user.
        
    Raises:
        HTTPException: 403 if analyst trying to access high/critical alert.
        HTTPException: 404 if alert not found.
        
    Returns:
        Alert ID and list of generated plans.
    """
    inc = await get_incident(alert_id)
    if not inc:
        raise HTTPException(404, "Alert not found")
    
    # Check if analyst is accessing high/critical priority alert
    priority = inc.get("priority", "").lower()
    if priority in ("high", "critical") and user.role == "analyst":
        raise HTTPException(
            403, 
            "High/Critical priority alerts require Admin or Senior Analyst access"
        )
    
    plans_data = inc.get("plans_generated") or {}
    # Handle both dict with 'plans' key and direct list
    if isinstance(plans_data, dict):
        plans_list = plans_data.get("plans", [])
    else:
        plans_list = plans_data if isinstance(plans_data, list) else []
    return {"alert_id": alert_id, "plans": plans_list}


@router.post("/{alert_id}/approve")
async def approve_plan(
    alert_id: str,
    body: ApprovalRequest,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above)
) -> dict:
    """Approve a remediation plan and publish to Kafka for execution.
    
    Validates all action types and checks for destructive actions that
    require admin or senior analyst approval.
    
    Args:
        alert_id: The alert identifier.
        body: Approval request with selected actions.
        user: Current authenticated user (from JWT).
        _: Role verification dependency (unused).
        
    Raises:
        HTTPException: 400 if unknown action type.
        HTTPException: 403 if analyst trying to approve destructive actions.
        HTTPException: 404 if alert not found.
        
    Returns:
        Confirmation with alert_id and plan_id.
    """
    # Get alert details to check priority and assignment
    inc = await get_incident(alert_id)
    if not inc:
        raise HTTPException(404, "Alert not found")

    # ── Ownership check ───────────────────────────────────────────────────────
    # Plans may only be acted on by the analyst the alert is assigned to.
    # Unassigned alerts cannot be approved by anyone.
    assigned_to = inc.get("assigned_to")
    if not assigned_to:
        raise HTTPException(
            403,
            "This alert is not assigned to anyone. "
            "Assign it to yourself before approving plans."
        )
    if assigned_to != user.username:
        raise HTTPException(
            403,
            f"This alert is assigned to '{assigned_to}'. "
            "Only the assigned analyst can approve plans."
        )

    # Check priority restrictions
    priority = inc.get("priority", "").lower()
    if priority in ("high", "critical") and user.role == "analyst":
        raise HTTPException(
            403,
            "Analysts cannot approve plans for High/Critical priority alerts. "
            "Admin or Senior Analyst approval required."
        )

    # Validate all action types are allowed
    for a in body.actions:
        if a.action_type not in ALLOWED:
            raise HTTPException(400, f"Unknown action type: {a.action_type}")

    # Check for destructive actions
    has_destructive = any(a.action_type in DESTRUCTIVE_ACTIONS for a in body.actions)
    if has_destructive and user.role not in ("admin", "senior_analyst"):
        raise HTTPException(
            403,
            "Destructive actions (firewall changes, isolation, credential rotation) "
            "require Admin or Senior Analyst approval."
        )
    
    # approved_by always from JWT - not request body
    await record_approval(
        alert_id, body.plan_id, user.username,
        [a.model_dump() for a in body.actions], body.notes, body.modifications
    )
    await publish_approval(
        alert_id, body.plan_id, [a.model_dump() for a in body.actions],
        user.username, body.notes or ""
    )
    
    # Send WebSocket notification
    await manager.broadcast("feed", {
        "type": "plan_approved",
        "alert_id": alert_id,
        "plan_id": body.plan_id,
        "approved_by": user.username,
        "priority": priority
    })
    
    return {"detail": "Plan approved", "alert_id": alert_id, "plan_id": body.plan_id}


@router.post("/{alert_id}/escalate")
async def escalate_for_approval(
    alert_id: str,
    body: EscalationRequest,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above)
) -> dict:
    """Escalate plan approval to admin/senior analyst.

    Persists the escalation to the database so it is visible to admins
    even if they are offline when the request is made.
    """
    import json as _json
    pool = await get_pool()
    async with pool.acquire() as conn:
        alert = await conn.fetchrow(
            "SELECT classification, priority, assigned_to FROM incidents WHERE alert_id = $1",
            alert_id
        )
        if not alert:
            raise HTTPException(404, "Alert not found")

        # ── Ownership check ────────────────────────────────────────────────────
        assigned_to = alert["assigned_to"]
        if not assigned_to:
            raise HTTPException(
                403,
                "This alert is not assigned to anyone. "
                "Assign it to yourself before escalating plans."
            )
        if assigned_to != user.username:
            raise HTTPException(
                403,
                f"This alert is assigned to '{assigned_to}'. "
                "Only the assigned analyst can escalate plans."
            )


        # Persist escalation record
        esc_id = await conn.fetchval(
            """INSERT INTO plan_escalations
               (alert_id, plan_id, escalated_by, reason, actions, status, created_at)
               VALUES ($1, $2, $3, $4, $5::jsonb, 'pending', NOW())
               RETURNING id""",
            alert_id, body.plan_id, user.username, body.reason,
            _json.dumps([a if isinstance(a, dict) else a.__dict__ for a in body.actions])
        )

        # Broadcast to all connected clients (admins/senior will see it live)
        await manager.broadcast("feed", {
            "type": "escalation_request",
            "escalation_id": esc_id,
            "alert_id": alert_id,
            "plan_id": body.plan_id,
            "requested_by": user.username,
            "priority": alert["priority"],
            "classification": alert["classification"],
            "reason": body.reason
        })

        # Email all admins and senior analysts
        admin_rows = await conn.fetch(
            "SELECT email, username FROM users WHERE role IN ('admin', 'senior_analyst') AND is_active = TRUE"
        )
        for admin in admin_rows:
            if admin["email"]:
                await email_service.send_email(
                    to_email=admin["email"],
                    subject=f"[ESCALATION] {alert['classification']} — {alert['priority'].upper()} priority",
                    html_content=f"""
                    <p>Hello {admin['username']},</p>
                    <p>Analyst <strong>{user.username}</strong> has escalated a plan for your approval.</p>
                    <div style="background:#1e293b;padding:15px;border-radius:5px;margin:20px 0;color:#e2e8f0;">
                        <p><strong>Alert:</strong> {alert['classification']}</p>
                        <p><strong>Priority:</strong> {alert['priority']}</p>
                        <p><strong>Reason:</strong> {body.reason}</p>
                    </div>
                    <p>Log in to the Sentinel dashboard → <em>Escalations</em> tab to review.</p>
                    """
                )

    logger.info(f"Escalation {esc_id} created by {user.username} for alert {alert_id}")
    return {
        "escalation_id": esc_id,
        "detail": "Escalation persisted and admins notified",
        "alert_id": alert_id,
        "plan_id": body.plan_id,
        "notified_admins": len(admin_rows)
    }


@router.get("/escalations")
async def list_escalations(
    status: Optional[str] = None,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    """List plan escalations.

    Admin and senior analysts see all pending escalations.
    Regular analysts only see their own.
    """
    from core.dependencies import senior_or_above
    pool = await get_pool()
    async with pool.acquire() as conn:
        is_elevated = user.role in ("admin", "senior_analyst")
        conds, params, i = [], [], 1

        if not is_elevated:
            conds.append(f"e.escalated_by = ${i}")
            params.append(user.username)
            i += 1

        if status:
            conds.append(f"e.status = ${i}")
            params.append(status)
            i += 1
        else:
            # Default: show pending only for elevated users
            if is_elevated:
                conds.append(f"e.status = 'pending'")

        where = ("WHERE " + " AND ".join(conds)) if conds else ""

        rows = await conn.fetch(
            f"""SELECT e.id, e.alert_id, e.plan_id, e.escalated_by, e.reason,
                       e.actions, e.status, e.picked_up_by, e.picked_up_at,
                       e.created_at, i.classification, i.priority, i.assigned_to
                FROM plan_escalations e
                JOIN incidents i ON i.alert_id = e.alert_id
                {where}
                ORDER BY
                    CASE i.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
                    e.created_at ASC
                LIMIT 100""",
            *params
        )

    items = []
    for row in rows:
        d = dict(row)
        for ts in ("created_at", "picked_up_at"):
            if d.get(ts):
                d[ts] = d[ts].isoformat()
        # actions is already jsonb, asyncpg returns it as a string
        if isinstance(d.get("actions"), str):
            import json as _json
            try:
                d["actions"] = _json.loads(d["actions"])
            except Exception:
                d["actions"] = []
        items.append(d)

    return {"items": items, "total": len(items)}


@router.post("/escalations/{escalation_id}/pickup")
async def pickup_escalation(
    escalation_id: int,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(senior_or_above)
) -> dict:
    """Pick up an escalated plan for review.

    Only admin or senior analysts may pick up escalations.
    Picking up:
      - Marks the escalation as picked_up
      - Reassigns the alert to the picking-up user
      - Broadcasts a WS update so the original analyst's view updates
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        esc = await conn.fetchrow(
            """SELECT e.*, i.classification, i.priority, i.assigned_to
               FROM plan_escalations e
               JOIN incidents i ON i.alert_id = e.alert_id
               WHERE e.id = $1""",
            escalation_id
        )
        if not esc:
            raise HTTPException(404, "Escalation not found")
        if esc["status"] != "pending":
            raise HTTPException(409, f"Escalation is already '{esc['status']}'")

        # Mark picked up
        await conn.execute(
            """UPDATE plan_escalations
               SET status = 'picked_up', picked_up_by = $1, picked_up_at = NOW()
               WHERE id = $2""",
            user.username, escalation_id
        )

        # Reassign alert from original analyst to the picking-up user
        await conn.execute(
            "UPDATE incidents SET assigned_to = $1 WHERE alert_id = $2",
            user.username, esc["alert_id"]
        )

    # Notify all clients
    await manager.broadcast("feed", {
        "type": "escalation_picked_up",
        "escalation_id": escalation_id,
        "alert_id": esc["alert_id"],
        "plan_id": esc["plan_id"],
        "picked_up_by": user.username,
        "original_analyst": esc["escalated_by"],
        "classification": esc["classification"],
        "priority": esc["priority"],
    })

    logger.info(f"Escalation {escalation_id} picked up by {user.username} (alert {esc['alert_id']})")
    return {
        "escalation_id": escalation_id,
        "status": "picked_up",
        "alert_id": esc["alert_id"],
        "plan_id": esc["plan_id"],
        "picked_up_by": user.username,
        "redirect_to": f"/alerts/{esc['alert_id']}/plans"
    }


class ReplanRequest(BaseModel):
    reason: str


@router.post("/{alert_id}/replan")
async def request_replan(
    alert_id: str,
    body: ReplanRequest,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above),
) -> dict:
    """Trigger a fresh investigation after rejecting unsatisfactory plans.

    Publishes a new message to the ``investigation-requests`` Kafka topic with
    the analyst's rejection reason as ``replan_context``.  The orchestrator
    passes this context to the LLM so it adjusts its strategy.
    """
    import json as _json, os, time
    from confluent_kafka import Producer

    pool = await get_pool()
    async with pool.acquire() as conn:
        alert = await conn.fetchrow(
            "SELECT approval_status, assigned_to FROM incidents WHERE alert_id=$1",
            alert_id,
        )
        if not alert:
            raise HTTPException(404, "Alert not found")
        if alert["assigned_to"] != user.username:
            raise HTTPException(
                403,
                f"Alert is assigned to '{alert['assigned_to']}'. "
                "Only the assigned analyst can request a replan.",
            )
        if alert["approval_status"] not in ("plans_generated", "rejected"):
            raise HTTPException(
                400,
                f"Cannot replan an alert with status '{alert['approval_status']}'.",
            )
        # Reset status so the UI shows investigation is running again
        await conn.execute(
            "UPDATE incidents SET approval_status='triaged' WHERE alert_id=$1",
            alert_id,
        )

    # Publish to Kafka — orchestrator picks this up and runs process_investigation
    # with replan_context set, which the LLM prompt surfaces to adjust strategy.
    try:
        bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
        producer = Producer({"bootstrap.servers": bootstrap})
        producer.produce(
            "investigation-requests",
            key=alert_id.encode(),
            value=_json.dumps({
                "alert_id":       alert_id,
                "requested_by":   user.username,
                "replan_context": body.reason,
                "timestamp":      time.time(),
            }).encode(),
        )
        producer.flush(timeout=5.0)
    except Exception as exc:
        logger.warning("Replan Kafka publish failed: %s", exc)

    await manager.broadcast("feed", {
        "type": "investigation_started",
        "alert_id": alert_id,
        "started_by": user.username,
        "replan": True,
    })

    return {"detail": "Replan requested", "alert_id": alert_id, "status": "triaged"}


@router.post("/{alert_id}/reject")
async def reject_plan(
    alert_id: str,
    body: dict,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above)
) -> dict:
    """Reject a remediation plan.
    
    Args:
        alert_id: The alert identifier.
        body: Rejection request with optional plan_id and reason.
        user: Current authenticated user (from JWT).
        _: Role verification dependency (unused).
        
    Returns:
        Confirmation message.
    """
    # Get alert details to check assignment
    inc = await get_incident(alert_id)
    if not inc:
        raise HTTPException(404, "Alert not found")

    # ── Ownership check ───────────────────────────────────────────────────────
    assigned_to = inc.get("assigned_to")
    if not assigned_to:
        raise HTTPException(
            403,
            "This alert is not assigned to anyone. "
            "Assign it to yourself before rejecting plans."
        )
    if assigned_to != user.username:
        raise HTTPException(
            403,
            f"This alert is assigned to '{assigned_to}'. "
            "Only the assigned analyst can reject plans."
        )

    await record_approval(
        alert_id, body.get("plan_id", ""), user.username,
        [], body.get("reason"), decision="rejected"
    )
    return {"detail": "Plan rejected"}