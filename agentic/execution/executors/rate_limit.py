"""
Rate Limit Executor
====================
Apply rate limiting to traffic from/to a specific IP or subnet.
Less disruptive than a full block — allows legitimate traffic through
while throttling potential attack traffic.

In production:
- tc/htb on Linux (traffic shaping)
- Cloud: WAF rate limiting rules (AWS WAF, Cloudflare)
- Load balancer rate limiting (nginx, HAProxy)
"""

import asyncio
import logging
import os

from agentic.execution.base_executor import BaseExecutor

logger = logging.getLogger(__name__)


class RateLimitExecutor(BaseExecutor):
    """Apply network rate limiting to a target IP or service."""

    @property
    def action_type(self) -> str:
        return "rate_limit"

    async def _validate(self, action: dict) -> tuple[bool, str]:
        target = action.get("target", "")
        params = action.get("params", {})

        if not target:
            return False, "Missing target IP or hostname"

        rate = params.get("requests_per_second")
        bandwidth = params.get("bandwidth_kbps")
        if not rate and not bandwidth:
            return False, "Must specify either requests_per_second or bandwidth_kbps"

        if rate and rate < 1:
            return False, "requests_per_second must be >= 1"

        return True, "Validation passed"

    async def _execute(self, action: dict) -> dict:
        target = action["target"]
        params = action.get("params", {})
        rate = params.get("requests_per_second", 10)
        bandwidth = params.get("bandwidth_kbps")
        duration_hours = params.get("duration_hours", 1)

        await asyncio.sleep(0.3)
        rule_id = f"rl-{target.replace('.', '-')}"

        logger.info(
            f"[SIMULATE] Rate limit applied: {rule_id} "
            f"target={target}, rate={rate} req/s, bandwidth={bandwidth} kbps, "
            f"duration={duration_hours}h"
        )

        return {
            "rule_id": rule_id,
            "target": target,
            "requests_per_second": rate,
            "bandwidth_kbps": bandwidth,
            "duration_hours": duration_hours,
        }

    async def _rollback(self, action: dict) -> tuple[bool, str]:
        target = action.get("target", "")
        await asyncio.sleep(0.2)
        return True, f"Rate limit for {target} removed"
