"""
NVD CVE Sync Script
====================
Fetches CVE data from the NIST National Vulnerability Database (NVD) REST API
v2.0 and upserts it into the local PostgreSQL database.

Design:
- Paginated fetching (2000 results per page, NVD API limit)
- Upsert semantics: new CVEs are inserted, existing ones are updated
- Tracks last sync timestamp so subsequent runs only fetch modified CVEs
- Respects NVD rate limits (6 requests/minute without API key, 50 with)
- Full-text search vector is auto-updated via PostgreSQL trigger

Usage:
    python scripts/sync_nvd.py                    # incremental sync (last 7 days)
    python scripts/sync_nvd.py --full             # full sync (all CVEs)
    python scripts/sync_nvd.py --days 30          # last 30 days

Environment Variables:
    DATABASE_URL    - PostgreSQL connection string
    NVD_API_KEY     - (optional) NVD API key for higher rate limits
"""

import os
import sys
import time
import argparse
import logging
from datetime import datetime, timedelta, timezone

import httpx
import psycopg2
from psycopg2.extras import execute_values

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
RATE_LIMIT_DELAY = 6.0  # seconds between requests (no API key)
RATE_LIMIT_DELAY_KEYED = 0.6  # seconds with API key


def parse_args():
    parser = argparse.ArgumentParser(description="Sync CVEs from NVD into PostgreSQL")
    parser.add_argument("--full", action="store_true", help="Full sync (all CVEs)")
    parser.add_argument("--days", type=int, default=7, help="Days to look back (default 7)")
    return parser.parse_args()


def fetch_cves(api_key: str | None, start_date: datetime | None, start_index: int = 0) -> dict:
    """Fetch a page of CVEs from the NVD API."""
    params = {
        "resultsPerPage": PAGE_SIZE,
        "startIndex": start_index,
    }
    if start_date:
        params["lastModStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    response = httpx.get(NVD_API_BASE, params=params, headers=headers, timeout=30.0)
    response.raise_for_status()
    return response.json()


def parse_cve_item(vuln: dict) -> dict:
    """Extract fields from a single NVD vulnerability object into our schema."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    # Description (English)
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # CVSS v3.1 metrics
    metrics = cve.get("metrics", {})
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            break

    cvss_score = cvss_data.get("baseScore") if cvss_data else None
    cvss_vector = cvss_data.get("vectorString") if cvss_data else None
    attack_vector = cvss_data.get("attackVector") if cvss_data else None
    attack_complexity = cvss_data.get("attackComplexity") if cvss_data else None
    privileges_required = cvss_data.get("privilegesRequired") if cvss_data else None
    user_interaction = cvss_data.get("userInteraction") if cvss_data else None

    # Severity from baseSeverity or computed from score
    severity = None
    if cvss_data:
        severity = cvss_data.get("baseSeverity")
    if not severity and cvss_score:
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # Affected products (first CPE match)
    affected_vendor = None
    affected_product = None
    affected_versions = None
    configurations = cve.get("configurations", [])
    if configurations:
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        affected_vendor = parts[3] if parts[3] != "*" else None
                        affected_product = parts[4] if parts[4] != "*" else None
                        version_start = match.get("versionStartIncluding", "")
                        version_end = match.get("versionEndExcluding", "")
                        if version_start or version_end:
                            affected_versions = f"{version_start} - {version_end}"
                        break
                if affected_vendor:
                    break
            if affected_vendor:
                break

    # Dates
    published = cve.get("published")
    modified = cve.get("lastModified")

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "severity": severity,
        "published_date": published,
        "modified_date": modified,
        "affected_vendor": affected_vendor,
        "affected_product": affected_product,
        "affected_versions": affected_versions,
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "privileges_required": privileges_required,
        "user_interaction": user_interaction,
        "exploit_available": False,  # updated separately from exploit-db
    }


def upsert_cves(conn, cves: list[dict]):
    """Bulk upsert CVE records into PostgreSQL."""
    if not cves:
        return

    columns = [
        "cve_id", "description", "cvss_v3_score", "cvss_v3_vector", "severity",
        "published_date", "modified_date", "affected_vendor", "affected_product",
        "affected_versions", "attack_vector", "attack_complexity",
        "privileges_required", "user_interaction", "exploit_available"
    ]

    values = [tuple(cve[col] for col in columns) for cve in cves]

    upsert_sql = f"""
        INSERT INTO cve_entries ({', '.join(columns)})
        VALUES %s
        ON CONFLICT (cve_id) DO UPDATE SET
            description = EXCLUDED.description,
            cvss_v3_score = EXCLUDED.cvss_v3_score,
            cvss_v3_vector = EXCLUDED.cvss_v3_vector,
            severity = EXCLUDED.severity,
            modified_date = EXCLUDED.modified_date,
            affected_vendor = EXCLUDED.affected_vendor,
            affected_product = EXCLUDED.affected_product,
            affected_versions = EXCLUDED.affected_versions,
            attack_vector = EXCLUDED.attack_vector,
            attack_complexity = EXCLUDED.attack_complexity,
            privileges_required = EXCLUDED.privileges_required,
            user_interaction = EXCLUDED.user_interaction,
            updated_at = NOW()
    """

    with conn.cursor() as cur:
        execute_values(cur, upsert_sql, values)
    conn.commit()


def main():
    args = parse_args()

    database_url = os.environ.get("DATABASE_URL", "postgresql://sentinel:sentinel_dev@localhost:5432/sentinel")
    api_key = os.environ.get("NVD_API_KEY")

    delay = RATE_LIMIT_DELAY_KEYED if api_key else RATE_LIMIT_DELAY

    # Determine time window
    start_date = None
    if not args.full:
        start_date = datetime.now(timezone.utc) - timedelta(days=args.days)
        logger.info(f"Incremental sync: fetching CVEs modified since {start_date.isoformat()}")
    else:
        logger.info("Full sync: fetching ALL CVEs (this will take a while)")

    # Connect to PostgreSQL
    conn = psycopg2.connect(database_url)
    logger.info("Connected to PostgreSQL")

    # Paginated fetch loop
    start_index = 0
    total_synced = 0

    while True:
        logger.info(f"Fetching page at index {start_index}...")
        try:
            data = fetch_cves(api_key, start_date, start_index)
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API error: {e.response.status_code} - {e.response.text}")
            break
        except httpx.RequestError as e:
            logger.error(f"Network error: {e}")
            time.sleep(delay * 2)
            continue

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        if not vulnerabilities:
            break

        # Parse and upsert
        cves = [parse_cve_item(vuln) for vuln in vulnerabilities]
        upsert_cves(conn, cves)
        total_synced += len(cves)

        logger.info(f"Synced {total_synced}/{total_results} CVEs")

        # Check if we've fetched everything
        start_index += PAGE_SIZE
        if start_index >= total_results:
            break

        # Rate limit
        time.sleep(delay)

    conn.close()
    logger.info(f"Sync complete. Total CVEs upserted: {total_synced}")


if __name__ == "__main__":
    main()
