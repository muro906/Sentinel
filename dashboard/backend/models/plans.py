"""Plan and approval-related Pydantic models."""

from typing import Optional

from pydantic import BaseModel


class ActionItem(BaseModel):
    """A single remediation action within an execution plan.
    
    Attributes:
        action_type: Type of action (e.g., 'firewall_block', 'isolate_host').
        target: The target resource (IP, hostname, etc.).
        parameters: Additional action-specific parameters.
        rationale: Justification for why this action is recommended.
    """
    action_type: str
    target: str
    parameters: dict = {}
    rationale: str = ""


class ApprovalRequest(BaseModel):
    """Request body for plan approval/rejection.
    
    Attributes:
        plan_id: Unique identifier of the plan being approved.
        actions: List of actions to approve.
        notes: Optional analyst notes.
        modifications: Optional description of modifications made to the plan.
    """
    plan_id: str
    actions: list[ActionItem]
    notes: Optional[str] = None
    modifications: Optional[str] = None