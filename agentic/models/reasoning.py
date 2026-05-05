"""
Reasoning Event Models
=======================
Every agent step emits a ReasoningEvent to provide full transparency to the
SOC analyst. These events form a chronological trace showing:
- WHAT each agent did
- WHAT data it used
- WHAT it produced
- WHY it made that decision
- HOW LONG it took

Events are published to a Redis Stream (for real-time WebSocket push) and
persisted to PostgreSQL (for audit and historical retrieval).
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class ReasoningEventType(str, Enum):
    """All possible event types in the reasoning trace."""
    # Orchestrator lifecycle
    ALERT_RECEIVED = "alert_received"
    TRIAGE_DECISION = "triage_decision"
    DUPLICATE_DETECTED = "duplicate_detected"

    # Sub-agent dispatch
    AGENT_DISPATCHED = "agent_dispatched"
    AGENT_RESULT = "agent_result"
    AGENT_TIMEOUT = "agent_timeout"
    AGENT_ERROR = "agent_error"

    # Planning
    CONTEXT_BUILT = "context_built"
    LLM_PROMPT = "llm_prompt"
    LLM_RESPONSE = "llm_response"
    PLAN_SCORED = "plan_scored"
    PLAN_PUBLISHED = "plan_published"

    # Human interaction
    APPROVAL_RECEIVED = "approval_received"
    REJECTION_RECEIVED = "rejection_received"
    APPROVAL_TIMEOUT = "approval_timeout"

    # Approval
    PLAN_APPROVED = "plan_approved"
    PLAN_REJECTED = "plan_rejected"

    # Execution
    EXECUTION_STARTED = "execution_started"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_RESULT = "execution_result"
    ACTION_STARTED = "action_started"
    ACTION_COMPLETED = "action_completed"
    ACTION_FAILED = "action_failed"
    ACTION_BLOCKED = "action_blocked"
    REPLAN_TRIGGERED = "replan_triggered"

    # Incident lifecycle
    INCIDENT_CLOSED = "incident_closed"
    INCIDENT_ESCALATED = "incident_escalated"


class ReasoningEvent(BaseModel):
    """
    A single step in the agent's reasoning chain.
    This is what gets displayed in the analyst's trace viewer.
    """
    event_id: str = Field(
        default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}",
        description="Unique event identifier"
    )
    alert_id: str = Field(..., description="Alert this event belongs to")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this event occurred"
    )
    event_type: ReasoningEventType = Field(..., description="Category of this event")

    # Who did what
    agent: str = Field(
        ...,
        description="Agent that emitted this event (orchestrator, cve_lookup, asset_discovery, planning)"
    )
    action: str = Field(
        ...,
        description="Human-readable description of what was done"
    )

    # Input/Output (two levels: summary for timeline, full for drill-down)
    input_summary: str = Field(
        default="",
        description="Condensed input for timeline display"
    )
    output_summary: str = Field(
        default="",
        description="Condensed output for timeline display"
    )
    full_input: Optional[dict] = Field(
        None,
        description="Complete input data (expandable in UI, e.g., full LLM prompt)"
    )
    full_output: Optional[dict] = Field(
        None,
        description="Complete output data (expandable in UI, e.g., full LLM response)"
    )

    # THE KEY FIELD: why this decision was made
    rationale: str = Field(
        ...,
        description="Human-readable explanation of WHY this decision was made"
    )

    # Metadata
    duration_ms: int = Field(0, description="How long this step took")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence if applicable")
    error: Optional[str] = Field(None, description="Error message if this step failed")

    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "evt-a1b2c3d4e5f6",
                "alert_id": "alert-x9y8z7",
                "timestamp": "2024-01-15T10:30:01Z",
                "event_type": "agent_result",
                "agent": "cve_lookup",
                "action": "Searched NVD for CVEs matching port 22 + openssh",
                "input_summary": "dst_port=22, service=openssh, conn_state=S0",
                "output_summary": "Found 2 CVEs: CVE-2024-6387 (cvss=8.1), CVE-2023-51385 (cvss=6.5)",
                "rationale": "Port 22 with SYN-only connections suggests SSH service reconnaissance. "
                             "Searched for openssh CVEs with network attack vector and CVSS >= 6.0. "
                             "CVE-2024-6387 (regreSSHion) is highest priority due to active exploitation.",
                "duration_ms": 45,
                "confidence": 0.85
            }
        }
