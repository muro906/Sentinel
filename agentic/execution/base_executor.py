"""
Base Executor
==============
Abstract base class for all action executors. Each executor handles one
action type (firewall_block, isolate_host, etc.) and wraps the actual
infrastructure API call with:

1. Pre-validation  — check action params before touching anything
2. Execution       — call the infrastructure API / CLI / SDK
3. Verification    — confirm the action took effect
4. Rollback        — undo the action if verification fails or on request
5. Reasoning       — emit events at every step for full transparency

Every executor returns an ActionResult with success/failure status,
duration, and any error details.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Optional

from agentic.models.plan import ActionResult
from agentic.models.reasoning import ReasoningEvent, ReasoningEventType
from agentic.reasoning.emitter import emit_reasoning_event

logger = logging.getLogger(__name__)


class BaseExecutor(ABC):
    """
    Abstract executor for a single action type.

    Subclasses implement:
        - action_type (property): matches the Action.type field
        - _validate(action): pre-flight checks
        - _execute(action): do the thing
        - _verify(action, exec_result): confirm it worked
        - _rollback(action): undo if needed
    """

    def __init__(self, dry_run: bool = False):
        """
        Args:
            dry_run: If True, log what WOULD happen without executing.
                     Used for testing and plan preview.
        """
        self.dry_run = dry_run

    @property
    @abstractmethod
    def action_type(self) -> str:
        """Action type this executor handles (e.g., 'firewall_block')."""
        ...

    @abstractmethod
    async def _validate(self, action: dict) -> tuple[bool, str]:
        """
        Validate action params before execution.
        Returns (is_valid, reason).
        """
        ...

    @abstractmethod
    async def _execute(self, action: dict) -> dict:
        """
        Execute the action. Returns result metadata dict.
        Raises on failure.
        """
        ...

    async def _verify(self, action: dict, exec_result: dict) -> tuple[bool, str]:
        """
        Verify the action took effect. Override for actions that support it.
        Default: assume success (no verification).
        """
        return True, "No verification implemented — assumed success"

    async def _rollback(self, action: dict) -> tuple[bool, str]:
        """
        Roll back the action. Override for reversible actions.
        Returns (success, message).
        """
        return False, f"Rollback not implemented for {self.action_type}"

    async def run(self, alert_id: str, action: dict) -> ActionResult:
        """
        Public entry point. Orchestrates validate → execute → verify
        with reasoning events and timing.
        """
        action_id = action.get("action_id", "unknown")
        target = action.get("target", "unknown")
        start_time = time.time()

        # ── Validate ──────────────────────────────────────────────
        is_valid, reason = await self._validate(action)
        if not is_valid:
            await emit_reasoning_event(ReasoningEvent(
                alert_id=alert_id,
                event_type=ReasoningEventType.ACTION_BLOCKED,
                agent="executor",
                action=f"Action {action_id} ({self.action_type}) BLOCKED: validation failed",
                input_summary=f"target={target}",
                rationale=f"Pre-validation failed: {reason}. Action will not be executed.",
                error=reason,
            ))
            return ActionResult(
                action_id=action_id,
                alert_id=alert_id,
                status="blocked",
                error=reason,
                duration_ms=int((time.time() - start_time) * 1000),
            )

        # ── Dry Run ───────────────────────────────────────────────
        if self.dry_run:
            await emit_reasoning_event(ReasoningEvent(
                alert_id=alert_id,
                event_type=ReasoningEventType.ACTION_STARTED,
                agent="executor",
                action=f"[DRY RUN] Would execute {self.action_type} on {target}",
                input_summary=f"target={target}, params={action.get('params', {})}",
                rationale="Dry-run mode — action logged but not executed.",
            ))
            return ActionResult(
                action_id=action_id,
                alert_id=alert_id,
                status="dry_run",
                output={"dry_run": True, "would_execute": self.action_type, "target": target},
                duration_ms=0,
            )

        # ── Execute ───────────────────────────────────────────────
        await emit_reasoning_event(ReasoningEvent(
            alert_id=alert_id,
            event_type=ReasoningEventType.ACTION_STARTED,
            agent="executor",
            action=f"Executing {self.action_type} on {target}",
            input_summary=f"target={target}, params={action.get('params', {})}",
            rationale=action.get("rationale", "No rationale provided"),
        ))

        try:
            exec_result = await self._execute(action)
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            error_msg = f"{type(e).__name__}: {e}"

            await emit_reasoning_event(ReasoningEvent(
                alert_id=alert_id,
                event_type=ReasoningEventType.ACTION_FAILED,
                agent="executor",
                action=f"Action {action_id} ({self.action_type}) FAILED on {target}",
                input_summary=f"target={target}",
                rationale=f"Execution failed: {error_msg}",
                duration_ms=duration_ms,
                error=error_msg,
            ))

            return ActionResult(
                action_id=action_id,
                alert_id=alert_id,
                status="failed",
                error=error_msg,
                duration_ms=duration_ms,
            )

        # ── Verify ────────────────────────────────────────────────
        verified, verify_msg = await self._verify(action, exec_result)
        duration_ms = int((time.time() - start_time) * 1000)

        if verified:
            await emit_reasoning_event(ReasoningEvent(
                alert_id=alert_id,
                event_type=ReasoningEventType.ACTION_COMPLETED,
                agent="executor",
                action=f"Action {action_id} ({self.action_type}) completed on {target}",
                output_summary=verify_msg,
                rationale=f"Action executed and verified successfully in {duration_ms}ms.",
                duration_ms=duration_ms,
            ))
            return ActionResult(
                action_id=action_id,
                alert_id=alert_id,
                status="completed",
                output=exec_result,
                duration_ms=duration_ms,
            )
        else:
            # Verification failed — attempt rollback if reversible
            if action.get("reversible", True):
                rb_ok, rb_msg = await self._rollback(action)
                logger.warning(f"Rollback after verify failure: {rb_ok}, {rb_msg}")

            await emit_reasoning_event(ReasoningEvent(
                alert_id=alert_id,
                event_type=ReasoningEventType.ACTION_FAILED,
                agent="executor",
                action=f"Action {action_id} verification FAILED on {target}",
                rationale=f"Execution ran but verification failed: {verify_msg}. "
                          f"{'Rollback attempted.' if action.get('reversible') else 'Not reversible.'}",
                duration_ms=duration_ms,
                error=verify_msg,
            ))
            return ActionResult(
                action_id=action_id,
                alert_id=alert_id,
                status="failed",
                error=f"Verification failed: {verify_msg}",
                output=exec_result,
                duration_ms=duration_ms,
            )
