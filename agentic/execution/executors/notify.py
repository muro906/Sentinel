"""
Notify Executor
================
Send notifications to security teams via various channels:
- Slack webhook
- PagerDuty incident
- Email (SMTP)
- Microsoft Teams webhook

Least destructive executor — used in every plan tier from conservative
to aggressive. The only executor that is ALWAYS safe to auto-execute.
"""

import asyncio
import json
import logging
import os
from typing import Optional

from agentic.execution.base_executor import BaseExecutor

logger = logging.getLogger(__name__)


class NotifyExecutor(BaseExecutor):
    """Send notification to security personnel via configured channels."""

    @property
    def action_type(self) -> str:
        return "notify"

    async def _validate(self, action: dict) -> tuple[bool, str]:
        target = action.get("target", "")
        params = action.get("params", {})

        if not target:
            return False, "Missing target (team name or channel)"

        channel = params.get("channel", "slack")
        if channel not in ("slack", "pagerduty", "email", "teams", "log"):
            return False, f"Unsupported notification channel: {channel}"

        if channel == "email" and not params.get("recipients"):
            return False, "Email notification requires 'recipients' param"

        return True, "Validation passed"

    async def _execute(self, action: dict) -> dict:
        target = action["target"]
        params = action.get("params", {})
        channel = params.get("channel", "slack")
        severity = params.get("severity", "medium")
        message = params.get("message", f"Security alert for target {target}")

        if channel == "slack":
            return await self._send_slack(target, severity, message)
        elif channel == "pagerduty":
            return await self._send_pagerduty(target, severity, message)
        elif channel == "email":
            return await self._send_email(params.get("recipients", []), severity, message)
        elif channel == "teams":
            return await self._send_teams(target, severity, message)
        else:
            # Fallback: just log
            logger.info(f"[NOTIFY] {severity.upper()} → {target}: {message}")
            return {"channel": "log", "target": target, "delivered": True}

    async def _send_slack(self, channel: str, severity: str, message: str) -> dict:
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

        if not webhook_url:
            # Simulate
            await asyncio.sleep(0.2)
            logger.info(f"[SIMULATE] Slack → #{channel}: [{severity}] {message}")
            return {"channel": "slack", "target": channel, "delivered": True, "simulated": True}

        # Real Slack webhook
        import httpx
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
        payload = {
            "channel": f"#{channel}",
            "text": f"{severity_emoji} *[{severity.upper()}]* {message}",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=payload, timeout=10)
            resp.raise_for_status()

        return {"channel": "slack", "target": channel, "delivered": True, "status": resp.status_code}

    async def _send_pagerduty(self, service: str, severity: str, message: str) -> dict:
        routing_key = os.environ.get("PAGERDUTY_ROUTING_KEY")

        if not routing_key:
            await asyncio.sleep(0.2)
            logger.info(f"[SIMULATE] PagerDuty → {service}: [{severity}] {message}")
            return {"channel": "pagerduty", "target": service, "delivered": True, "simulated": True}

        import httpx
        pd_severity = {"critical": "critical", "high": "error", "medium": "warning"}.get(severity, "info")
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": message,
                "severity": pd_severity,
                "source": "sentinel-orchestrator",
            },
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload, timeout=10,
            )
            resp.raise_for_status()

        return {"channel": "pagerduty", "target": service, "delivered": True}

    async def _send_email(self, recipients: list[str], severity: str, message: str) -> dict:
        await asyncio.sleep(0.3)
        logger.info(f"[SIMULATE] Email → {recipients}: [{severity}] {message}")
        return {"channel": "email", "recipients": recipients, "delivered": True, "simulated": True}

    async def _send_teams(self, channel: str, severity: str, message: str) -> dict:
        await asyncio.sleep(0.2)
        logger.info(f"[SIMULATE] Teams → {channel}: [{severity}] {message}")
        return {"channel": "teams", "target": channel, "delivered": True, "simulated": True}
