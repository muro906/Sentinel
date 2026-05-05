"""
Action Router
==============
Routes approved actions to the correct executor based on action type.
Manages the execution pipeline for a full plan:

1. Order actions by dependency (sequential by default)
2. Route each action to the matching executor
3. Collect results and report back to Kafka
4. Emit reasoning events for the full execution lifecycle

The router is invoked by the ApprovalHandler when a plan is approved.
"""

import asyncio
import logging
import time
from typing import Optional

from agentic.execution.base_executor import BaseExecutor
from agentic.models.plan import ActionResult
from agentic.models.reasoning import ReasoningEvent, ReasoningEventType
from agentic.reasoning.emitter import emit_reasoning_event

logger = logging.getLogger(__name__)

# Executor registry — populated by register_executor()
_EXECUTOR_REGISTRY: dict[str, BaseExecutor] = {}


def register_executor(executor: BaseExecutor):
    """Register an executor instance for a given action type."""
    _EXECUTOR_REGISTRY[executor.action_type] = executor
    logger.debug(f"Registered executor: {executor.action_type}")


def get_executor(action_type: str) -> Optional[BaseExecutor]:
    """Look up the executor for an action type."""
    return _EXECUTOR_REGISTRY.get(action_type)


def list_executors() -> list[str]:
    """Return all registered action types."""
    return list(_EXECUTOR_REGISTRY.keys())


async def execute_plan(
    alert_id: str,
    plan_id: str,
    actions: list[dict],
    stop_on_failure: bool = True,
) -> list[ActionResult]:
    """
    Execute all actions in a plan sequentially.

    Args:
        alert_id: Alert this plan belongs to
        plan_id: Plan identifier
        actions: Ordered list of action dicts
        stop_on_failure: If True, abort remaining actions after first failure

    Returns:
        List of ActionResult for each action (completed + failed + skipped)
    """
    results = []
    start_time = time.time()

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert_id,
        event_type=ReasoningEventType.EXECUTION_STARTED,
        agent="executor",
        action=f"Starting execution of plan {plan_id}: {len(actions)} actions",
        input_summary=f"Actions: {[a.get('type', '?') for a in actions]}",
        rationale=f"Plan {plan_id} approved. Executing {len(actions)} actions sequentially. "
                  f"Stop on failure: {stop_on_failure}.",
    ))

    failed = False
    for i, action in enumerate(actions):
        action_type = action.get("type", "unknown")
        action_id = action.get("action_id", f"act-{i}")

        # Skip remaining actions if a previous one failed
        if failed and stop_on_failure:
            results.append(ActionResult(
                action_id=action_id,
                alert_id=alert_id,
                status="skipped",
                error="Skipped due to previous action failure",
                duration_ms=0,
            ))
            continue

        # Find the executor
        executor = get_executor(action_type)
        if executor is None:
            logger.error(f"No executor registered for action type: {action_type}")
            result = ActionResult(
                action_id=action_id,
                alert_id=alert_id,
                status="failed",
                error=f"No executor for action type '{action_type}'",
                duration_ms=0,
            )
            results.append(result)
            failed = True
            continue

        # Execute the action
        result = await executor.run(alert_id, action)
        results.append(result)

        if result.status == "failed":
            failed = True
            logger.warning(f"Action {action_id} failed: {result.error}")

    # Emit completion event
    total_ms = int((time.time() - start_time) * 1000)
    completed = sum(1 for r in results if r.status == "completed")
    failed_count = sum(1 for r in results if r.status == "failed")
    skipped = sum(1 for r in results if r.status == "skipped")

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert_id,
        event_type=ReasoningEventType.EXECUTION_COMPLETED if not failed_count
                   else ReasoningEventType.EXECUTION_FAILED,
        agent="executor",
        action=f"Plan {plan_id} execution {'completed' if not failed_count else 'completed with failures'}",
        output_summary=f"Completed: {completed}, Failed: {failed_count}, Skipped: {skipped}",
        rationale=f"Executed {completed + failed_count}/{len(actions)} actions in {total_ms}ms. "
                  + (f"All actions succeeded." if not failed_count
                     else f"{failed_count} action(s) failed. {skipped} skipped."),
        duration_ms=total_ms,
    ))

    return results


def init_executors(dry_run: bool = False):
    """
    Register all built-in executors. Called at startup.

    Args:
        dry_run: If True, all executors log but don't actually execute.
    """
    from agentic.execution.executors.firewall import FirewallBlockExecutor, FirewallUnblockExecutor
    from agentic.execution.executors.isolate import IsolateHostExecutor, RestoreHostExecutor
    from agentic.execution.executors.patch import PatchExecutor
    from agentic.execution.executors.notify import NotifyExecutor
    from agentic.execution.executors.inspect import DeepInspectExecutor
    from agentic.execution.executors.rate_limit import RateLimitExecutor
    from agentic.execution.executors.credential import CredentialRotateExecutor

    for cls in [
        FirewallBlockExecutor, FirewallUnblockExecutor,
        IsolateHostExecutor, RestoreHostExecutor,
        PatchExecutor, NotifyExecutor, DeepInspectExecutor,
        RateLimitExecutor, CredentialRotateExecutor,
    ]:
        register_executor(cls(dry_run=dry_run))

    logger.info(f"Registered {len(_EXECUTOR_REGISTRY)} executors (dry_run={dry_run})")
