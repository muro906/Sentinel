"""CVE (Common Vulnerabilities and Exposures) router."""

import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query

from core.dependencies import analyst_or_above
from db.cves import get_cve, list_cves, upsert_cves

logger = logging.getLogger(__name__)
router = APIRouter()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_nvd_vuln(vuln: dict) -> Optional[Dict[str, Any]]:
    """Parse one NVD vulnerability object into our cve_entries schema."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )

    metrics = cve.get("metrics", {})
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        primary = next((e for e in entries if e.get("type") == "Primary"), None)
        raw = (primary or (entries[0] if entries else None))
        if raw:
            cvss_data = raw.get("cvssData", {})
            break

    score    = cvss_data.get("baseScore")   if cvss_data else None
    vector   = cvss_data.get("vectorString") if cvss_data else None
    severity = cvss_data.get("baseSeverity") if cvss_data else None
    if not severity and score is not None:
        severity = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7
                    else "MEDIUM" if score >= 4 else "LOW")

    attack_vector        = cvss_data.get("attackVector")        if cvss_data else None
    attack_complexity    = cvss_data.get("attackComplexity")    if cvss_data else None
    privileges_required  = cvss_data.get("privilegesRequired")  if cvss_data else None
    user_interaction     = cvss_data.get("userInteraction")     if cvss_data else None

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

    exploit_available = any(
        "Exploit" in ref.get("tags", []) for ref in cve.get("references", [])
    )

    return {
        "cve_id": cve_id, "description": description,
        "cvss_v3_score": score, "cvss_v3_vector": vector, "severity": severity,
        "published_date": cve.get("published"), "modified_date": cve.get("lastModified"),
        "affected_vendor": affected_vendor, "affected_product": affected_product,
        "affected_versions": affected_versions,
        "attack_vector": attack_vector, "attack_complexity": attack_complexity,
        "privileges_required": privileges_required, "user_interaction": user_interaction,
        "exploit_available": exploit_available,
    }


async def _fetch_nvd(keyword: str, limit: int, min_cvss: float, exploit_only: bool) -> List[dict]:
    """Query NVD API and return parsed CVE records sorted by CVSS score."""
    import os
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    params: dict = {"keywordSearch": keyword, "resultsPerPage": min(limit * 4, 100)}
    if exploit_only:
        params["hasKev"] = ""           # NVD filter: Known Exploited Vulnerabilities

    async with httpx.AsyncClient(timeout=25.0) as client:
        resp = await client.get(NVD_API_URL, params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    parsed = []
    for vuln in data.get("vulnerabilities", []):
        rec = _parse_nvd_vuln(vuln)
        if rec and (rec["cvss_v3_score"] or 0) >= min_cvss:
            if exploit_only and not rec["exploit_available"]:
                continue
            parsed.append(rec)

    parsed.sort(key=lambda r: r["cvss_v3_score"] or 0, reverse=True)
    return parsed[:limit]


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("")
async def list_cves_ep(
    search: Optional[str] = Query(None),
    min_cvss: float = Query(0.0, ge=0.0, le=10.0),
    attack_vector: Optional[str] = Query(None),
    exploit_only: bool = Query(False),
    page: int = Query(1, ge=1),
    limit: int = Query(100, le=500),
    _: None = Depends(analyst_or_above),
) -> dict:
    """List CVEs from local DB with filtering and pagination."""
    return await list_cves(
        search=search, min_cvss=min_cvss, attack_vector=attack_vector,
        exploit_only=exploit_only, page=page, limit=limit,
    )


@router.get("/search-nvd")
async def search_nvd(
    q: str = Query(..., min_length=2, description="Search keyword"),
    limit: int = Query(20, ge=1, le=100),
    min_cvss: float = Query(0.0, ge=0.0, le=10.0),
    exploit_only: bool = Query(False),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    _: None = Depends(analyst_or_above),
) -> dict:
    """Query NIST NVD API live and cache results in the local table.

    The returned CVEs are also upserted into cve_entries so they appear
    in the main CVE Browser view on future visits.
    """
    try:
        cves = await _fetch_nvd(q, limit, min_cvss, exploit_only)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(502, f"NVD API error: {exc.response.status_code}")
    except Exception as exc:
        raise HTTPException(502, f"NVD unreachable: {exc}")

    if cves:
        # Persist in background so the response returns immediately
        background_tasks.add_task(upsert_cves, cves)

    return {"items": cves, "total": len(cves), "source": "nvd"}


@router.get("/{cve_id}")
async def get_cve_ep(cve_id: str, _: None = Depends(analyst_or_above)) -> dict:
    """Get a specific CVE by ID from local DB."""
    cve = await get_cve(cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    return cve
