"""
Host Isolation Executors
=========================
Isolate a compromised host from the network or restore connectivity.

In production, isolation is achieved via:
- VLAN reassignment (switch API)
- Endpoint agent kill-switch (CrowdStrike, SentinelOne, osquery)
- SDN policy (VMware NSX, Cisco ACI)
- Cloud: move instance to quarantine security group

This is the most destructive executor — it completely cuts network access.
Protected hosts (DNS, DC, management) cannot be isolated.
"""

import asyncio
import logging
import os

from agentic.execution.base_executor import BaseExecutor

logger = logging.getLogger(__name__)


class IsolateHostExecutor(BaseExecutor):
    """Isolate a host from the network (quarantine)."""

    @property
    def action_type(self) -> str:
        return "isolate_host"

    async def _validate(self, action: dict) -> tuple[bool, str]:
        target = action.get("target", "")
        if not target:
            return False, "Missing target hostname or IP"

        # Never isolate critical infrastructure
        protected = os.environ.get(
            "PROTECTED_HOSTS",
            "dns-resolver,auth-server,dc-01,mgmt-switch"
        ).split(",")
        if target in protected:
            return False, (
                f"Host '{target}' is protected critical infrastructure — "
                f"isolation would cause cascading failures. "
                f"Use targeted firewall rules instead."
            )

        return True, "Validation passed"

    async def _execute(self, action: dict) -> dict:
        target = action["target"]
        params = action.get("params", {})
        method = params.get("method", "vlan_quarantine")

        await asyncio.sleep(1.0)  # simulate switch/agent API call
        logger.info(f"[SIMULATE] Isolated host {target} via {method}")

        return {
            "target": target,
            "method": method,
            "isolated": True,
            "previous_vlan": params.get("current_vlan", "unknown"),
            "quarantine_vlan": "999",
        }

    async def _verify(self, action: dict, exec_result: dict) -> tuple[bool, str]:
        target = exec_result.get("target", "")
        # In production: ping test should fail, or check switch port state
        await asyncio.sleep(0.3)
        return True, f"Host {target} confirmed isolated (no network response)"

    async def _rollback(self, action: dict) -> tuple[bool, str]:
        target = action.get("target", "")
        logger.info(f"Rolling back isolation for {target}")
        await asyncio.sleep(0.5)
        return True, f"Host {target} restored to original VLAN"


class RestoreHostExecutor(BaseExecutor):
    """Restore a previously isolated host to normal network connectivity."""

    @property
    def action_type(self) -> str:
        return "restore_host"

    async def _validate(self, action: dict) -> tuple[bool, str]:
        if not action.get("target"):
            return False, "Missing target hostname or IP"
        return True, "Validation passed"

    async def _execute(self, action: dict) -> dict:
        target = action["target"]
        params = action.get("params", {})
        original_vlan = params.get("original_vlan", "unknown")

        await asyncio.sleep(0.5)
        logger.info(f"[SIMULATE] Restored host {target} to VLAN {original_vlan}")

        return {"target": target, "restored": True, "vlan": original_vlan}
