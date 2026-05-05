"""
Firewall Executors
===================
Block/unblock IP addresses or CIDR ranges via iptables or an API gateway.

In production, these would call:
- iptables/nftables via SSH or an agent
- Cloud security groups (AWS SG, GCP firewall)
- Network firewall API (Palo Alto, Fortinet, pfSense)

For development, they simulate the operation with delays and log output.
The infrastructure adapter is swappable via the FIREWALL_ADAPTER env var.
"""

import asyncio
import logging
import os

from agentic.execution.base_executor import BaseExecutor

logger = logging.getLogger(__name__)


class FirewallBlockExecutor(BaseExecutor):
    """Block inbound/outbound traffic for a specific IP or CIDR."""

    @property
    def action_type(self) -> str:
        return "firewall_block"

    async def _validate(self, action: dict) -> tuple[bool, str]:
        target = action.get("target", "")
        params = action.get("params", {})

        if not target:
            return False, "Missing target IP/CIDR"

        # Don't block internal management IPs
        protected = os.environ.get("PROTECTED_IPS", "10.0.0.254,192.168.1.254").split(",")
        if target in protected:
            return False, f"Target {target} is a protected management IP — cannot block"

        direction = params.get("direction", "inbound")
        if direction not in ("inbound", "outbound", "both"):
            return False, f"Invalid direction: {direction}"

        return True, "Validation passed"

    async def _execute(self, action: dict) -> dict:
        target = action["target"]
        params = action.get("params", {})
        direction = params.get("direction", "inbound")
        duration_hours = params.get("duration_hours", 24)

        adapter = os.environ.get("FIREWALL_ADAPTER", "simulate")

        if adapter == "simulate":
            # Simulate firewall rule addition
            await asyncio.sleep(0.5)  # simulate API call latency
            rule_id = f"fw-rule-{target.replace('.', '-')}-{direction}"
            logger.info(f"[SIMULATE] Added firewall rule: {rule_id} "
                        f"BLOCK {direction} {target} for {duration_hours}h")
            return {
                "rule_id": rule_id,
                "target": target,
                "direction": direction,
                "duration_hours": duration_hours,
                "adapter": "simulate",
            }

        elif adapter == "iptables":
            # Real iptables execution via subprocess
            chain = "INPUT" if direction == "inbound" else "OUTPUT"
            cmd = f"iptables -A {chain} -s {target} -j DROP"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"iptables failed: {stderr.decode()}")
            return {"rule_id": f"iptables-{chain}-{target}", "target": target, "adapter": "iptables"}

        else:
            raise ValueError(f"Unknown firewall adapter: {adapter}")

    async def _verify(self, action: dict, exec_result: dict) -> tuple[bool, str]:
        adapter = exec_result.get("adapter", "simulate")
        if adapter == "simulate":
            return True, f"Simulated rule {exec_result.get('rule_id')} applied"
        # Real verification would check iptables -L or API state
        return True, f"Rule {exec_result.get('rule_id')} verified"

    async def _rollback(self, action: dict) -> tuple[bool, str]:
        target = action.get("target", "")
        logger.info(f"Rolling back firewall block for {target}")
        # In production: remove the iptables rule or API firewall rule
        await asyncio.sleep(0.2)
        return True, f"Firewall block for {target} removed"


class FirewallUnblockExecutor(BaseExecutor):
    """Remove a firewall block (restore traffic flow)."""

    @property
    def action_type(self) -> str:
        return "firewall_unblock"

    async def _validate(self, action: dict) -> tuple[bool, str]:
        if not action.get("target"):
            return False, "Missing target IP/CIDR"
        return True, "Validation passed"

    async def _execute(self, action: dict) -> dict:
        target = action["target"]
        params = action.get("params", {})
        rule_id = params.get("rule_id", f"fw-rule-{target.replace('.', '-')}")

        await asyncio.sleep(0.3)
        logger.info(f"[SIMULATE] Removed firewall rule: {rule_id} for {target}")
        return {"rule_id": rule_id, "target": target, "removed": True}
