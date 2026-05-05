"""
Context Builder
================
Transforms a ThreatBundle dict into a structured LLM prompt using Jinja2
templates. The prompt contains all the context the LLM needs to generate
informed execution plans:

- System role and instructions
- Alert details (what triggered the alert)
- CVE context (matched vulnerabilities)
- Asset context (what's at risk, blast radius)
- Historical context (how similar incidents were handled)
- Output format instructions (structured JSON)

The prompt is designed for Mistral 7B Instruct format with [INST] tags.
"""

import os
import logging

from jinja2 import Environment, FileSystemLoader, Template

logger = logging.getLogger(__name__)

# Template directory
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "prompts")

# Fallback inline template if file not found
FALLBACK_TEMPLATE = """[INST]
You are an expert cybersecurity incident responder working in a Security Operations Center (SOC).
Your role is to analyze threat intelligence and generate execution plans to respond to detected anomalies.

## ALERT DETAILS
- Alert ID: {{ alert.alert_id }}
- Classification: {{ alert.classification }}
- Anomaly Score: {{ alert.anomaly_score }}
- Source: {{ alert.feature_vector.src_ip }}:{{ alert.feature_vector.src_port }}
- Destination: {{ alert.feature_vector.dst_ip }}:{{ alert.feature_vector.dst_port }}
- Protocol: {{ alert.feature_vector.proto }}
- Connection State: {{ alert.feature_vector.conn_state | default('unknown') }}

## CVE MATCHES ({{ cve_matches | length }} found)
{% for cve in cve_matches %}
- {{ cve.cve_id }} (CVSS: {{ cve.cvss_score }}, {{ cve.severity }})
  Product: {{ cve.affected_product | default('N/A') }}
  Exploit available: {{ cve.exploit_available }}
  Match rationale: {{ cve.match_rationale }}
{% endfor %}
{% if not cve_matches %}
No CVE matches found for this traffic pattern.
{% endif %}

## AFFECTED ASSETS ({{ affected_assets | length }} found)
{% for asset in affected_assets %}
- {{ asset.hostname }} ({{ asset.ip_address }})
  Criticality: Tier {{ asset.criticality_tier }}
  OS: {{ asset.os | default('unknown') }}
  Zone: {{ asset.network_zone.zone_name if asset.network_zone else 'unknown' }}
  Services: {% for svc in asset.services %}{{ svc.service_name }}:{{ svc.port }}{% if not loop.last %}, {% endif %}{% endfor %}
  Blast radius: {{ asset.blast_radius }}
  Dependents: {{ asset.downstream_dependents | length }}
{% endfor %}
{% if not affected_assets %}
No known assets resolved for the involved IPs.
{% endif %}

## RISK SUMMARY
- Priority: {{ priority | upper }}
- Maximum CVSS: {{ max_cvss }}
- Total Blast Radius: {{ total_blast_radius }}
- Active Exploit: {{ has_active_exploit }}

## INSTRUCTIONS
Generate exactly 3 execution plans with different aggression levels:

1. **Conservative** — Minimal disruption. Monitor, alert, and investigate.
2. **Moderate** — Targeted containment. Block specific traffic, notify teams.
3. **Aggressive** — Full containment. Isolate hosts, block IPs, rotate credentials.

For each plan, provide:
- plan_id: unique string
- confidence: float 0.0-1.0 (how confident you are this plan addresses the threat)
- risk_level: "low", "medium", "high", or "critical"
- aggression: "conservative", "moderate", or "aggressive"
- threat_summary: one paragraph describing the threat and proposed response
- actions: array of action objects, each with:
  - type: one of "firewall_block", "firewall_unblock", "isolate_host", "restore_host", "patch", "notify", "deep_inspect", "rate_limit", "credential_rotate"
  - target: IP address, hostname, or team name
  - params: object with action-specific parameters
  - rationale: why this action is needed
  - reversible: boolean
  - estimated_duration_seconds: integer

Respond ONLY with valid JSON in this format:
{
  "plans": [
    {
      "plan_id": "plan-001",
      "confidence": 0.85,
      "risk_level": "medium",
      "aggression": "moderate",
      "threat_summary": "...",
      "actions": [...]
    }
  ]
}
[/INST]"""


def build_prompt(threat_bundle: dict) -> str:
    """
    Build the LLM prompt from a ThreatBundle dict.

    Tries to load the Jinja2 template from file first (allows customization
    without code changes). Falls back to the inline template.
    """
    try:
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template("threat_response.jinja2")
        logger.debug("Using file-based prompt template")
    except Exception:
        template = Environment().from_string(FALLBACK_TEMPLATE)
        logger.debug("Using fallback inline prompt template")

    # Flatten the ThreatBundle for template rendering
    context = {
        "alert": threat_bundle.get("alert", {}),
        "cve_matches": threat_bundle.get("cve_matches", []),
        "affected_assets": threat_bundle.get("affected_assets", []),
        "similar_incidents": threat_bundle.get("similar_incidents", []),
        "priority": threat_bundle.get("priority", "unknown"),
        "max_cvss": threat_bundle.get("max_cvss", 0),
        "total_blast_radius": threat_bundle.get("total_blast_radius", 0),
        "has_active_exploit": threat_bundle.get("has_active_exploit", False),
    }

    prompt = template.render(**context)
    logger.info(f"Built LLM prompt: {len(prompt)} chars")
    return prompt
