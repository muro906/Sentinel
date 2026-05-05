"""
Deep Inspect Executor
======================
Triggers extended packet capture and traffic analysis for a specific
alert or target. Used in conservative plans to gather more evidence
before taking disruptive action.

In production:
- Starts a targeted Zeek or tcpdump capture on the network tap
- Activates enhanced logging on the target host
- Queues the traffic for ML re-analysis with lower thresholds
"""

import asyncio
import logging

from agentic.execution.base_executor import BaseExecutor

logger = logging.getLogger(__name__)


class DeepInspectExecutor(BaseExecutor):
    """Start extended monitoring/capture for deeper analysis."""

    @property
    def action_type(self) -> str:
        return "deep_inspect"

    async def _validate(self, action: dict) -> tuple[bool, str]:
        params = action.get("params", {})
        duration = params.get("duration_minutes", 30)

        if duration > 1440:  # 24 hours max
            return False, f"Inspection duration {duration}min exceeds 24h maximum"
        if duration < 1:
            return False, "Minimum inspection duration is 1 minute"

        return True, "Validation passed"

    async def _execute(self, action: dict) -> dict:
        target = action.get("target", "alert_traffic")
        params = action.get("params", {})
        duration_minutes = params.get("duration_minutes", 30)
        alert_id = params.get("alert_id", "unknown")
        capture_filter = params.get("bpf_filter", "")

        await asyncio.sleep(0.5)
        capture_id = f"cap-{alert_id[:8]}-{target.replace('.', '-')}"

        logger.info(
            f"[SIMULATE] Started deep inspection: {capture_id} "
            f"target={target}, duration={duration_minutes}min"
        )

        return {
            "capture_id": capture_id,
            "target": target,
            "duration_minutes": duration_minutes,
            "bpf_filter": capture_filter,
            "status": "capturing",
        }

    async def _rollback(self, action: dict) -> tuple[bool, str]:
        # Can always stop a capture early
        await asyncio.sleep(0.2)
        return True, "Inspection capture stopped"
