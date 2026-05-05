"""
CVE Lookup Agent
=================
Maps traffic characteristics from the anomaly alert to known CVE exploits.

Process:
1. EXTRACT SIGNATURES — Analyze the feature vector to determine what kind
   of attack this looks like and what services are targeted.
2. BUILD QUERIES — Translate signatures into database search parameters.
3. SEARCH CVE DATABASE — Run multiple query strategies (full-text, product,
   attack pattern) and merge results.
4. SCORE RELEVANCE — Rank matched CVEs by how well they match the observed
   traffic, weighting CVSS score, exploit availability, and signature match.

The agent emits reasoning events explaining WHY it chose certain search
strategies and WHY certain CVEs were ranked higher than others.
"""

import logging
from typing import Optional

from agentic.agents.base import BaseAgent
from agentic.db import cve_repository
from agentic.models.cve import CVEMatch

logger = logging.getLogger(__name__)

# Port → service mapping for signature extraction
PORT_SERVICE_MAP = {
    21: "ftp", 22: "openssh", 23: "telnet", 25: "smtp",
    53: "bind", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http", 8443: "https",
    9200: "elasticsearch", 27017: "mongodb",
}

# Connection states indicating attack patterns
SCAN_STATES = {"S0", "REJ", "RSTOS0", "RSTRH"}
EXPLOIT_STATES = {"RSTO", "S1", "SH"}


class CVELookupAgent(BaseAgent):
    """
    Sub-agent that searches the CVE database for exploits matching
    the traffic characteristics of an anomaly alert.
    """

    @property
    def name(self) -> str:
        return "cve_lookup"

    async def _process(self, task_data: dict) -> dict:
        """
        Core CVE lookup logic.

        Input (task_data keys):
            - dst_port: target port
            - proto: protocol (tcp/udp)
            - conn_state: connection state (S0, SF, REJ, etc.)
            - service: zeek-identified service (if any)
            - classification: attack classification from detection layer
            - ssl_version: TLS version (if applicable)
            - dns_query: DNS query (if applicable)
            - bytes_ratio: traffic ratio
            - src_ip, dst_ip: involved IPs

        Output:
            - matches: list of CVEMatch dicts
            - signatures: extracted signatures
            - _confidence: overall confidence in matches
        """
        # Step 1: Extract signatures from traffic features
        signatures = self._extract_signatures(task_data)

        # Step 2: Build and execute queries based on signatures
        all_matches = []

        for sig in signatures:
            matches = await self._query_for_signature(sig)
            all_matches.extend(matches)

        # Step 3: Deduplicate and score
        scored_matches = self._score_and_deduplicate(all_matches, task_data)

        # Step 4: Build result
        top_matches = scored_matches[:5]  # return top 5

        return {
            "matches": [m.model_dump() for m in top_matches],
            "signatures": signatures,
            "total_candidates": len(all_matches),
            "top_match": top_matches[0].model_dump() if top_matches else None,
            "_confidence": top_matches[0].match_confidence if top_matches else 0.0,
        }

    def _extract_signatures(self, task_data: dict) -> list[dict]:
        """
        Analyze traffic features and extract searchable signatures.
        Each signature represents a hypothesis about what exploit/vulnerability
        the traffic might be targeting.
        """
        signatures = []
        dst_port = task_data.get("dst_port")
        conn_state = task_data.get("conn_state", "")
        classification = task_data.get("classification", "")
        ssl_version = task_data.get("ssl_version")
        dns_query = task_data.get("dns_query")
        proto = task_data.get("proto", "tcp")
        service = task_data.get("service")
        bytes_ratio = task_data.get("bytes_ratio", 0)

        # Signature 1: Port → specific service vulnerability
        if dst_port:
            target_service = service or PORT_SERVICE_MAP.get(dst_port)
            if target_service:
                signatures.append({
                    "type": "service_vuln",
                    "service": target_service,
                    "port": dst_port,
                    "keywords": [target_service],
                    "rationale": f"Target port {dst_port} maps to service '{target_service}'"
                })

        # Signature 2: Connection state → attack pattern
        if conn_state in SCAN_STATES:
            signatures.append({
                "type": "reconnaissance",
                "attack_pattern": "port_scan" if conn_state == "S0" else "connection_probe",
                "keywords": ["scan", "reconnaissance", "enumeration"],
                "attack_vector": "NETWORK",
                "privileges_required": "NONE",
                "rationale": f"Connection state '{conn_state}' indicates reconnaissance "
                             f"(SYN sent, no response/rejected)"
            })

        if conn_state in EXPLOIT_STATES:
            signatures.append({
                "type": "exploit_attempt",
                "attack_pattern": "exploit",
                "keywords": ["remote code execution", "buffer overflow", "pre-auth"],
                "attack_vector": "NETWORK",
                "min_cvss": 7.0,
                "rationale": f"Connection state '{conn_state}' suggests active exploit attempt "
                             f"(connection established then abnormally terminated)"
            })

        # Signature 3: SSL/TLS vulnerability
        if ssl_version and ssl_version in ("SSLv3", "TLSv10", "TLSv1"):
            signatures.append({
                "type": "weak_tls",
                "keywords": [ssl_version.lower(), "ssl", "tls", "downgrade"],
                "rationale": f"Deprecated TLS version '{ssl_version}' in use — "
                             f"known vulnerabilities (POODLE, BEAST, etc.)"
            })

        # Signature 4: DNS-based attack
        if dns_query or classification == "dns_tunneling":
            signatures.append({
                "type": "dns_attack",
                "keywords": ["dns", "tunneling", "exfiltration", "dga"],
                "rationale": "DNS-based anomaly detected — possible tunneling or DGA communication"
            })

        # Signature 5: Data exfiltration pattern
        if classification == "data_exfiltration" or (bytes_ratio and bytes_ratio > 5.0):
            signatures.append({
                "type": "exfiltration",
                "keywords": ["exfiltration", "data theft", "command and control", "c2"],
                "rationale": f"High outbound byte ratio ({bytes_ratio:.1f}) suggests data exfiltration"
            })

        # Fallback: if no specific signatures, search by classification
        if not signatures and classification:
            signatures.append({
                "type": "generic",
                "keywords": classification.replace("_", " ").split(),
                "attack_vector": "NETWORK",
                "rationale": f"Generic search based on classification '{classification}'"
            })

        return signatures

    async def _query_for_signature(self, signature: dict) -> list[dict]:
        """Execute appropriate database queries for a given signature."""
        matches = []
        sig_type = signature.get("type", "generic")

        if sig_type == "service_vuln":
            # Search by product name
            results = await cve_repository.search_by_product(
                product=signature["service"],
                min_cvss=4.0,
                limit=5,
            )
            for r in results:
                r["_matched_signature"] = f"dst_port={signature.get('port')}, service={signature['service']}"
                r["_sig_type"] = sig_type
            matches.extend(results)

        if sig_type in ("reconnaissance", "exploit_attempt"):
            # Search by attack pattern
            results = await cve_repository.search_by_attack_pattern(
                attack_vector=signature.get("attack_vector", "NETWORK"),
                privileges_required=signature.get("privileges_required", "NONE"),
                min_cvss=signature.get("min_cvss", 6.0),
                limit=5,
            )
            for r in results:
                r["_matched_signature"] = f"attack_pattern={signature.get('attack_pattern')}"
                r["_sig_type"] = sig_type
            matches.extend(results)

        # Always do keyword search
        if signature.get("keywords"):
            results = await cve_repository.search_by_keywords(
                keywords=signature["keywords"],
                min_cvss=4.0,
                attack_vector=signature.get("attack_vector"),
                limit=5,
            )
            for r in results:
                r["_matched_signature"] = f"keywords={signature['keywords']}"
                r["_sig_type"] = sig_type
            matches.extend(results)

        return matches

    def _score_and_deduplicate(self, raw_matches: list[dict], task_data: dict) -> list[CVEMatch]:
        """
        Score and deduplicate CVE matches. Scoring formula:
            confidence = (cvss_weight * 0.4) + (exploit_bonus * 0.3) + (signature_match * 0.3)
        """
        seen_cves = {}

        for match in raw_matches:
            cve_id = match.get("cve_id")
            if not cve_id:
                continue

            # Calculate confidence score
            cvss = match.get("cvss_v3_score") or 0.0
            cvss_weight = min(cvss / 10.0, 1.0)

            exploit_bonus = 0.8 if match.get("exploit_available") else 0.2
            sig_type = match.get("_sig_type", "generic")
            sig_match = {"service_vuln": 0.9, "exploit_attempt": 0.8,
                         "reconnaissance": 0.6, "weak_tls": 0.9,
                         "dns_attack": 0.7, "exfiltration": 0.6}.get(sig_type, 0.4)

            confidence = (cvss_weight * 0.4) + (exploit_bonus * 0.3) + (sig_match * 0.3)

            # Keep highest confidence per CVE
            if cve_id not in seen_cves or confidence > seen_cves[cve_id].match_confidence:
                seen_cves[cve_id] = CVEMatch(
                    cve_id=cve_id,
                    cvss_score=cvss,
                    severity=match.get("severity", "UNKNOWN"),
                    description=match.get("description", "")[:500],
                    affected_product=match.get("affected_product"),
                    affected_versions=match.get("affected_versions"),
                    exploit_available=match.get("exploit_available", False),
                    matched_signature=match.get("_matched_signature", "unknown"),
                    match_confidence=round(confidence, 3),
                    match_rationale=self._build_rationale(match, confidence),
                )

        # Sort by confidence descending
        sorted_matches = sorted(seen_cves.values(), key=lambda m: m.match_confidence, reverse=True)
        return sorted_matches

    def _build_rationale(self, match: dict, confidence: float) -> str:
        """Build a human-readable rationale for why this CVE was matched."""
        parts = [f"Matched via {match.get('_matched_signature', 'keyword search')}."]

        cvss = match.get("cvss_v3_score")
        if cvss:
            parts.append(f"CVSS {cvss}/10 ({match.get('severity', 'N/A')}).")

        if match.get("exploit_available"):
            parts.append("Known exploit exists in the wild.")

        if match.get("affected_product"):
            parts.append(f"Affects {match['affected_product']}")
            if match.get("affected_versions"):
                parts.append(f"versions {match['affected_versions']}.")
            else:
                parts.append("(version unspecified).")

        parts.append(f"Match confidence: {confidence:.0%}.")
        return " ".join(parts)

    def _summarize_output(self, result: dict) -> str:
        """Human-readable summary for the reasoning trace."""
        matches = result.get("matches", [])
        if not matches:
            return "No CVE matches found"
        top = matches[0]
        return (
            f"Found {len(matches)} CVEs. Top: {top['cve_id']} "
            f"(cvss={top['cvss_score']}, confidence={top['match_confidence']:.0%})"
        )

    def _explain_result(self, result: dict) -> str:
        """Detailed rationale for the reasoning trace."""
        sigs = result.get("signatures", [])
        matches = result.get("matches", [])
        total = result.get("total_candidates", 0)

        parts = [f"Extracted {len(sigs)} signatures from traffic features."]
        for sig in sigs:
            parts.append(f"  - {sig.get('type')}: {sig.get('rationale', '')}")

        parts.append(f"Searched CVE database: {total} candidates found, {len(matches)} after scoring.")

        if matches:
            top = matches[0]
            parts.append(
                f"Top match: {top['cve_id']} ({top['severity']}, cvss={top['cvss_score']}) — "
                f"{top['match_rationale']}"
            )

        return "\n".join(parts)
