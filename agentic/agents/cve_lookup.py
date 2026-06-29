"""CVE Lookup Agent — queries NIST NVD API v2.0 in real-time.

Each investigation triggers a live NVD search with service/classification
keywords. Results are upserted into the local cve_entries table so the
CVE Browser in the dashboard stays populated as alerts are processed.

Falls back to the local DB if NVD is unreachable.
"""
import asyncio
import logging
import os
import re
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Port → canonical service keyword for NVD keyword search
_PORT_SERVICE = {
    21: "ftp",        22: "ssh",       23: "telnet",
    25: "smtp",       53: "dns",       80: "http",
    110: "pop3",      143: "imap",     389: "ldap",
    443: "https ssl", 445: "smb",      1433: "mssql",
    3306: "mysql",    3389: "rdp remote desktop",
    5432: "postgresql", 5900: "vnc",  6379: "redis",
    8080: "http",     8443: "https",  27017: "mongodb",
}

# Fragments inside classification strings that map to better NVD search terms
_CLASS_KEYWORDS = {
    "log4shell":    "log4j log4shell",
    "log4j":        "log4j",
    "eternalblue":  "eternalblue smb windows",
    "bluekeep":     "bluekeep rdp cve-2019-0708",
    "heartbleed":   "heartbleed openssl",
    "shellshock":   "shellshock bash",
    "wannacry":     "wannacry smb ransomware",
    "sql_inject":   "sql injection",
    "exfiltrat":    "data exfiltration",
    "brute_force":  "brute force authentication",
    "portscan":     "port scan reconnaissance",
    "smb":          "smb windows",
    "ssh":          "ssh openssh",
    "rdp":          "rdp remote desktop",
    "http":         "http web",
    "dns":          "dns",
    "ftp":          "ftp",
    "mysql":        "mysql database",
    "redis":        "redis",
    "mongodb":      "mongodb",
}


def _extract_keywords(service: Optional[str], classification: str, dst_port: int) -> str:
    """Derive compact NVD search keywords from alert metadata."""
    parts: List[str] = []

    # 1. explicit service hint
    if service and service not in ("-", ""):
        parts.append(service)

    # 2. port-derived service
    port_svc = _PORT_SERVICE.get(dst_port, "")
    if port_svc and port_svc not in " ".join(parts):
        parts.append(port_svc)

    # 3. classification fragments
    cls_lower = classification.lower()
    for fragment, keyword in _CLASS_KEYWORDS.items():
        if fragment in cls_lower:
            for kw in keyword.split():
                if kw not in " ".join(parts):
                    parts.append(kw)
            break  # one match is enough

    return " ".join(parts[:6]) or classification.replace("_", " ")


def _parse_nvd_vuln(vuln: dict) -> Optional[Dict[str, Any]]:
    """Parse a single NVD vulnerability object into our cve_entries schema."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # English description
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        ""
    )

    # CVSS v3.x metrics (prefer v3.1, fall back to v3.0)
    metrics = cve.get("metrics", {})
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        # prefer Primary source
        primary = next((e for e in entries if e.get("type") == "Primary"), None)
        cvss_data = (primary or (entries[0] if entries else None))
        if cvss_data:
            cvss_data = cvss_data.get("cvssData", {})
            break

    score = cvss_data.get("baseScore") if cvss_data else None
    vector = cvss_data.get("vectorString") if cvss_data else None
    severity = (cvss_data.get("baseSeverity") if cvss_data else None) or _score_to_severity(score)
    attack_vector = cvss_data.get("attackVector") if cvss_data else None
    attack_complexity = cvss_data.get("attackComplexity") if cvss_data else None
    privileges_required = cvss_data.get("privilegesRequired") if cvss_data else None
    user_interaction = cvss_data.get("userInteraction") if cvss_data else None

    # Affected product from CPE
    affected_vendor = affected_product = affected_versions = None
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5:
                    affected_vendor  = parts[3] if parts[3] != "*" else None
                    affected_product = parts[4] if parts[4] != "*" else None
                    vs = match.get("versionStartIncluding", "")
                    ve = match.get("versionEndExcluding", "")
                    if vs or ve:
                        affected_versions = f"{vs} - {ve}".strip(" -")
                    break
            if affected_vendor:
                break
        if affected_vendor:
            break

    # Exploit available: check NVD reference tags
    exploit_available = any(
        "Exploit" in ref.get("tags", [])
        for ref in cve.get("references", [])
    )

    return {
        "cve_id":              cve_id,
        "description":         description,
        "cvss_v3_score":       score,
        "cvss_v3_vector":      vector,
        "severity":            severity,
        "published_date":      cve.get("published"),
        "modified_date":       cve.get("lastModified"),
        "affected_vendor":     affected_vendor,
        "affected_product":    affected_product,
        "affected_versions":   affected_versions,
        "attack_vector":       attack_vector,
        "attack_complexity":   attack_complexity,
        "privileges_required": privileges_required,
        "user_interaction":    user_interaction,
        "exploit_available":   exploit_available,
    }


def _score_to_severity(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


async def _upsert_to_db(cves: List[Dict[str, Any]]) -> None:
    """Write NVD results into cve_entries so the CVE Browser shows them."""
    if not cves:
        return
    try:
        import asyncpg
        conn = await asyncpg.connect(
            os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel")
        )
        try:
            for c in cves:
                await conn.execute(
                    """
                    INSERT INTO cve_entries (
                        cve_id, description, cvss_v3_score, cvss_v3_vector, severity,
                        published_date, modified_date, affected_vendor, affected_product,
                        affected_versions, attack_vector, attack_complexity,
                        privileges_required, user_interaction, exploit_available
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        description        = EXCLUDED.description,
                        cvss_v3_score      = EXCLUDED.cvss_v3_score,
                        severity           = EXCLUDED.severity,
                        modified_date      = EXCLUDED.modified_date,
                        exploit_available  = EXCLUDED.exploit_available
                    """,
                    c["cve_id"], c["description"], c["cvss_v3_score"], c["cvss_v3_vector"],
                    c["severity"], c["published_date"], c["modified_date"],
                    c["affected_vendor"], c["affected_product"], c["affected_versions"],
                    c["attack_vector"], c["attack_complexity"],
                    c["privileges_required"], c["user_interaction"], c["exploit_available"],
                )
        finally:
            await conn.close()
    except Exception as exc:
        logger.warning("CVE upsert to local DB failed: %s", exc)


async def _query_local_db(service: str, classification: str) -> List[Dict[str, Any]]:
    """Fallback: search the local cve_entries table."""
    try:
        import asyncpg
        conn = await asyncpg.connect(
            os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel")
        )
        try:
            rows = await conn.fetch(
                """
                SELECT cve_id, cvss_v3_score, severity, description,
                       affected_product, affected_versions, exploit_available
                FROM cve_entries
                WHERE affected_product ILIKE $1 OR description ILIKE $2
                ORDER BY cvss_v3_score DESC NULLS LAST
                LIMIT 5
                """,
                f"%{service}%",
                f"%{classification.replace('_', ' ')}%",
            )
            return [dict(r) for r in rows]
        finally:
            await conn.close()
    except Exception as exc:
        logger.warning("Local CVE DB query failed: %s", exc)
        return []


class CVELookupAgent:
    """Queries NIST NVD API for CVEs relevant to the alert's service/classification."""

    async def lookup(
        self,
        dst_port: int,
        service: Optional[str],
        classification: str,
    ) -> List[Dict[str, Any]]:
        keyword = _extract_keywords(service, classification, dst_port)
        logger.info("CVE NVD search: '%s' (port=%d, service=%s)", keyword, dst_port, service)

        try:
            results = await self._query_nvd(keyword)
        except Exception as exc:
            logger.warning("NVD API unavailable (%s), using local DB", exc)
            results = []

        if results:
            # Persist to local DB so the CVE Browser reflects real data
            asyncio.create_task(_upsert_to_db(results))
            logger.info("Found %d CVEs from NVD for '%s'", len(results), keyword)
            return results

        # NVD returned nothing or failed — fall back to local seed data
        logger.info("Falling back to local CVE DB for '%s'", keyword)
        svc = service or _PORT_SERVICE.get(dst_port, "")
        return await _query_local_db(svc, classification)

    async def _query_nvd(self, keyword: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Query NVD API v2.0 with keyword search.
        NVD rate limit: 5 req/30 s (no key) — each investigation makes one call.
        """
        api_key = os.getenv("NVD_API_KEY")
        headers = {"apiKey": api_key} if api_key else {}
        params = {
            "keywordSearch":  keyword,
            "resultsPerPage": limit * 3,   # fetch more, then take top by CVSS
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(NVD_API_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        parsed = []
        for vuln in data.get("vulnerabilities", []):
            rec = _parse_nvd_vuln(vuln)
            if rec and rec["cvss_v3_score"] is not None:
                parsed.append(rec)

        # Return top entries by CVSS score
        parsed.sort(key=lambda r: r["cvss_v3_score"] or 0, reverse=True)
        return parsed[:limit]
