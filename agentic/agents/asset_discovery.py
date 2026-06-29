"""Asset Discovery Agent — network reconnaissance for a given alert.

For each alert the agent concurrently:
  1. Pings the destination IP to test reachability
  2. Resolves its hostname via nslookup
  3. Queries WHOIS for ownership information
  4. Looks the IP up in the local asset inventory (PostgreSQL)
  5. Runs a fast nmap scan to enumerate open ports
  6. Counts active TCP connections from the source IP via ss

All six probes run in parallel with asyncio.gather; individual failures are
silently swallowed so a single unreachable probe cannot block the pipeline.
"""
import asyncio
import logging
import os
from typing import Optional, Dict, Any, List

import asyncpg

logger = logging.getLogger(__name__)

_DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel")

# RFC-1918 + loopback prefixes used to classify source IPs as internal.
# str.startswith() accepts a tuple directly, so this is used as-is in _assess_source.
_PRIVATE_PREFIXES = (
    "10.", "127.", "192.168.",
    *[f"172.{i}." for i in range(16, 32)],
)

# WHOIS field names that carry the owning organisation, in priority order.
_WHOIS_FIELDS = ("orgname:", "org-name:", "organization:", "netname:")

# Lazy asyncpg pool — shared across all discover() calls in this process.
_pool: asyncpg.Pool | None = None


async def _get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(_DB_URL, min_size=1, max_size=5)
    return _pool


def _safe(v: Any, default: Any) -> Any:
    """Return default if v is an Exception, otherwise return v as-is.

    Used after asyncio.gather(return_exceptions=True) to replace failed
    sub-task results with harmless defaults without raising.
    """
    return default if isinstance(v, Exception) else v


class AssetDiscoveryAgent:

    async def discover(self, src_ip: str, dst_ip: str, dst_port: int) -> Dict[str, Any]:
        """Run all six reconnaissance probes concurrently and merge their results.

        Returns a dict with keys:
          dst_reachable, dst_hostname, dst_ownership, open_ports,
          local_asset, active_connections, source_assessment
        """
        src_ip, dst_ip = str(src_ip), str(dst_ip)

        # Launch all probes at once; individual failures are captured as Exception
        # instances rather than propagating, so one slow/broken probe cannot block the rest.
        (reachable, hostname, ownership,
         local_asset, open_ports, active_conns) = await asyncio.gather(
            self._ping(dst_ip),
            self._nslookup(dst_ip),
            self._whois(dst_ip),
            self._check_local_asset_db(dst_ip),
            self._nmap_scan(dst_ip),
            self._active_connections(src_ip),
            return_exceptions=True,
        )

        result = {
            "dst_reachable":      _safe(reachable, None),
            "dst_hostname":       _safe(hostname, None),
            "dst_ownership":      _safe(ownership, None),
            "open_ports":         _safe(open_ports, []),
            "local_asset":        _safe(local_asset, None),
            "active_connections": _safe(active_conns, 0),
            # Derived synchronously from the source IP — no I/O needed.
            "source_assessment":  self._assess_source(src_ip),
        }
        logger.info(
            "Asset discovery done for %s: reachable=%s open_ports=%s",
            dst_ip, result["dst_reachable"], result["open_ports"],
        )
        return result

    # ── Private helpers ────────────────────────────────────────────────────────

    async def _ping(self, ip: str) -> bool:
        """Return True if the host responds to a single ICMP echo within 2 s."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "2", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=4)
            return proc.returncode == 0
        except Exception:
            return False

    async def _nslookup(self, ip: str) -> Optional[str]:
        """Reverse-resolve ip to a hostname; returns None if resolution fails."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=6)
            for line in stdout.decode().splitlines():
                if "name =" in line.lower():
                    return line.split("=", 1)[1].strip().rstrip(".")
            return None
        except Exception:
            return None

    async def _whois(self, ip: str) -> Optional[str]:
        """Return the owning organisation name from WHOIS output, or None."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "whois", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12)
            # Lowercase each line once to avoid repeated .lower() in the inner check.
            for line in stdout.decode().splitlines():
                line_lower = line.lower()
                for field in _WHOIS_FIELDS:
                    if line_lower.startswith(field):
                        return line.split(":", 1)[1].strip()
            return None
        except Exception:
            return None

    async def _nmap_scan(self, ip: str) -> List[int]:
        """Fast nmap scan (-F top-100 ports); returns list of open port numbers.

        Uses grepable output (-oG -) because it's cheaper to parse than XML
        and doesn't require a temporary file.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-F", "--open", "-oG", "-", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            ports: List[int] = []
            for line in stdout.decode().splitlines():
                if "Ports:" not in line:
                    continue
                # Each chunk looks like "22/open/tcp//ssh///" — extract the port number.
                for chunk in line.split("Ports:", 1)[1].split(","):
                    chunk = chunk.strip()
                    if "/open/" in chunk:
                        try:
                            ports.append(int(chunk.split("/")[0]))
                        except ValueError:
                            pass
            return ports
        except Exception:
            return []

    async def _active_connections(self, src_ip: str) -> int:
        """Count established TCP connections that involve src_ip using ss."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ss", "-tn",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            return sum(1 for line in stdout.decode().splitlines() if src_ip in line)
        except Exception:
            return 0

    async def _check_local_asset_db(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up ip in the asset inventory; returns a dict row or None.

        Uses the shared connection pool to avoid a per-call TCP handshake.
        """
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    """SELECT a.ip_address::text, a.hostname, a.criticality_tier,
                              z.zone_name AS zone, a.owner
                       FROM assets a
                       LEFT JOIN network_zones z ON z.id = a.zone_id
                       WHERE a.ip_address = $1
                       LIMIT 1""",
                    ip,
                )
                return dict(row) if row else None
        except Exception as e:
            logger.debug("Asset DB lookup failed: %s", e)
            return None

    def _assess_source(self, src_ip: str) -> str:
        """Classify the alert source as internal or external based on its IP range."""
        if src_ip.startswith(_PRIVATE_PREFIXES):
            return "Internal host — possible lateral movement or insider threat"
        return "External host — likely attacker or compromised external system"
