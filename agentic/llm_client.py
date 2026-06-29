"""LLM client — multi-provider with automatic fallback.

Priority (first configured key wins as primary):
  1. Google Gemini Flash  — GOOGLE_API_KEY  (free tier, fast, reliable)
  2. Anthropic Claude     — ANTHROPIC_API_KEY
  3. Groq Llama           — GROQ_API_KEY    (free tier, fast fallback)
"""
import json
import logging
import os
import re
from typing import Any, Dict, List

from openai import AsyncOpenAI

logger = logging.getLogger("llm_client")

_PROVIDERS = []  # ordered list of active (name, client, model) tuples


class LLMClient:
    """Multi-provider LLM client with automatic fallback."""

    def __init__(self):
        self._providers: List[tuple] = []   # (name, caller, model)
        self._claude = None

        from openai import AsyncOpenAI

        google_key    = os.getenv("GOOGLE_API_KEY")
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        groq_key      = os.getenv("GROQ_API_KEY")

        if google_key:
            client = AsyncOpenAI(
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                api_key=google_key,
                timeout=30.0,
            )
            model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
            self._providers.append(("gemini", client, model))
            logger.info("LLM provider: Gemini (%s)", model)

        if anthropic_key:
            try:
                import anthropic
                self._claude = anthropic.AsyncAnthropic(api_key=anthropic_key)
                model = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
                self._providers.append(("claude", self._claude, model))
                logger.info("LLM provider: Claude (%s)", model)
            except ImportError:
                logger.warning("anthropic package not installed — skipping Claude")

        if groq_key:
            client = AsyncOpenAI(
                base_url="https://api.groq.com/openai/v1",
                api_key=groq_key,
                timeout=60.0,
            )
            model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
            self._providers.append(("groq", client, model))
            logger.info("LLM provider: Groq (%s)", model)

        if not self._providers:
            raise ValueError(
                "No LLM API key found. Set GOOGLE_API_KEY, ANTHROPIC_API_KEY, or GROQ_API_KEY."
            )

    # ── Low-level callers ──────────────────────────────────────────────────────

    async def _call_openai_compat(
        self, client: AsyncOpenAI, model: str, system: str, user: str, max_tokens: int
    ) -> str:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            temperature=0.4,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content

    async def _call_claude(self, client, model: str, system: str, user: str, max_tokens: int) -> str:
        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

    async def _chat(self, system: str, user: str, max_tokens: int = 2500) -> str:
        """Try each configured provider in order, falling back on error."""
        last_err = None
        for name, client, model in self._providers:
            try:
                if name == "claude":
                    return await self._call_claude(client, model, system, user, max_tokens)
                else:
                    return await self._call_openai_compat(client, model, system, user, max_tokens)
            except Exception as exc:
                logger.warning("LLM %s failed, trying next provider: %s", name, exc)
                last_err = exc
        raise RuntimeError(f"All LLM providers failed: {last_err}")

    # ── JSON extraction ────────────────────────────────────────────────────────

    def _extract_json(self, raw: str) -> dict:
        """Parse JSON from response, stripping markdown fences if present."""
        cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```\s*$", "", cleaned.strip(), flags=re.MULTILINE).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        return {}

    # ── Plan generation ────────────────────────────────────────────────────────

    async def generate_plans(
        self,
        alert: Dict[str, Any],
        asset_context: Dict[str, Any],
        cve_matches: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        system = (
            "You are a cybersecurity incident response expert. "
            "Generate structured JSON remediation plans. "
            "Return ONLY valid JSON — no prose, no markdown code fences."
        )
        prompt = self._build_plan_prompt(alert, asset_context, cve_matches)
        try:
            raw = await self._chat(system, prompt, max_tokens=2500)
            logger.info("Plan LLM response: %d chars", len(raw))
            return self._parse_plans(raw)
        except Exception as exc:
            logger.error("Plan LLM call failed: %s", exc)
            return self._fallback_plan(alert)

    def _build_plan_prompt(
        self,
        alert: Dict[str, Any],
        asset_context: Dict[str, Any],
        cve_matches: List[Dict[str, Any]],
    ) -> str:
        fv       = alert.get("feature_vector", {})
        src_ip   = str(alert.get("src_ip")  or fv.get("src_ip",  "unknown"))
        dst_ip   = str(alert.get("dst_ip")  or fv.get("dst_ip",  "unknown"))
        dst_port = alert.get("dst_port")    or fv.get("dst_port", 0)
        cls_     = alert.get("classification", "unknown")
        score    = alert.get("anomaly_score", 0)

        asset_lines = []
        if asset_context.get("dst_hostname"):
            asset_lines.append(f"Target hostname: {asset_context['dst_hostname']}")
        if asset_context.get("dst_ownership"):
            asset_lines.append(f"IP owner: {asset_context['dst_ownership']}")
        if asset_context.get("dst_reachable") is not None:
            asset_lines.append(f"Reachable: {asset_context['dst_reachable']}")
        if asset_context.get("open_ports"):
            asset_lines.append(f"Open ports: {asset_context['open_ports']}")
        if asset_context.get("source_assessment"):
            asset_lines.append(f"Source assessment: {asset_context['source_assessment']}")
        if asset_context.get("local_asset"):
            la = asset_context["local_asset"]
            asset_lines.append(
                f"Local asset: {la.get('hostname','?')} "
                f"tier={la.get('criticality_tier','?')} zone={la.get('zone','?')}"
            )

        cve_lines = [
            f"- {c.get('cve_id')}: CVSS {c.get('cvss_v3_score','N/A')} "
            f"({c.get('severity','?')}), {c.get('description','')[:80]}, "
            f"exploit={'YES' if c.get('exploit_available') else 'no'}"
            for c in cve_matches[:3]
        ]

        replan_note = alert.get("replan_note", "")
        replan_section = (
            f"\nPRIOR PLAN FAILURE / REPLAN CONTEXT:\n{replan_note}\n"
            "Take this into account — previous actions were insufficient. "
            "Adjust your strategy accordingly.\n"
        ) if replan_note else ""

        return f"""You are a senior incident-response analyst.
A network anomaly detector flagged the traffic below.{replan_section}

STEP 1 — CLASSIFY THE ATTACK
Reason about what attack technique this most likely represents.
Use the destination port, anomaly score, CVE matches, and classification hint.
If the hint is "network_anomaly" or "unknown", infer the technique from context.

ALERT:
- Raw classification hint: {cls_}
- Source IP: {src_ip} ({asset_context.get("source_assessment", "unknown origin")})
- Destination IP: {dst_ip}, Port: {dst_port}
- Anomaly Score: {score:.3f}

ASSET CONTEXT:
{chr(10).join(asset_lines) if asset_lines else "Asset not in inventory — treat as unknown host."}

MATCHED CVEs (ordered by CVSS score):
{chr(10).join(cve_lines) if cve_lines else "No CVE matches — rely on traffic patterns and asset context."}

STEP 2 — GENERATE EXACTLY 3 REMEDIATION PLANS
Each plan's rationale must begin with your attack classification.
Plans must differ in aggression: conservative, moderate, aggressive.

Return ONLY valid JSON (no code fences, no prose):
{{
  "plans": [
    {{
      "plan_id": "plan-conservative",
      "automation_tier": "conservative",
      "confidence": 0.80,
      "risk_level": "low",
      "rationale": "[ATTACK TYPE]: <classification reasoning>. Conservative: <what this plan does and why>.",
      "actions": [
        {{
          "action_type": "notify",
          "target": "security-team",
          "parameters": {{"severity": "high", "channel": "slack"}},
          "rationale": "Alert SOC analysts for manual review of {dst_port}/tcp traffic."
        }}
      ]
    }},
    {{
      "plan_id": "plan-moderate",
      "automation_tier": "moderate",
      "confidence": 0.75,
      "risk_level": "medium",
      "rationale": "...",
      "actions": [...]
    }},
    {{
      "plan_id": "plan-aggressive",
      "automation_tier": "aggressive",
      "confidence": 0.65,
      "risk_level": "high",
      "rationale": "...",
      "actions": [...]
    }}
  ]
}}

Allowed action_type values ONLY: notify, deep_inspect, rate_limit, firewall_block, firewall_unblock, isolate_host, credential_rotate, patch
Each plan must have 2-4 actions. Name the actual CVE, asset hostname, and port in rationale fields."""

    def _parse_plans(self, raw: str) -> List[Dict[str, Any]]:
        try:
            data  = self._extract_json(raw)
            plans = data.get("plans", data) if isinstance(data, dict) else data
            if not isinstance(plans, list):
                plans = [plans]
            normalized = []
            for plan in plans:
                norm = {
                    "plan_id":        plan.get("plan_id", f"plan-{len(normalized)+1}"),
                    "automation_tier": plan.get("automation_tier", "moderate"),
                    "confidence":      float(plan.get("confidence", 0.5)),
                    "risk_level":      plan.get("risk_level", "medium"),
                    "rationale":       plan.get("rationale", plan.get("threat_summary", "")),
                    "actions":         [],
                }
                for a in plan.get("actions", []):
                    norm["actions"].append({
                        "action_type": a.get("action_type", a.get("type", "notify")),
                        "target":      a.get("target", ""),
                        "parameters":  a.get("parameters", a.get("params", {})),
                        "rationale":   a.get("rationale", ""),
                    })
                normalized.append(norm)
            return normalized
        except Exception:
            logger.error("Failed to parse plan JSON from LLM")
            return []

    def _fallback_plan(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        fv     = alert.get("feature_vector", {})
        src_ip = str(alert.get("src_ip") or fv.get("src_ip", "unknown"))
        return [{
            "plan_id":         "fallback-conservative",
            "automation_tier": "conservative",
            "confidence":      0.3,
            "risk_level":      "low",
            "rationale":       "LLM unavailable. Fallback: notify and inspect.",
            "actions": [
                {"action_type": "notify",       "target": "security-team",
                 "parameters": {"severity": "high"}, "rationale": "Alert team for manual review"},
                {"action_type": "deep_inspect", "target": src_ip,
                 "parameters": {"packet_count": 30}, "rationale": "Capture evidence"},
            ],
        }]

    # ── Execution command generation ───────────────────────────────────────────

    async def generate_execution_commands(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        alert_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        system = (
            "You are a Linux sysadmin generating shell commands for security incident response. "
            "Generate safe, targeted commands. Return ONLY valid JSON — no prose, no code fences."
        )
        prompt = self._build_command_prompt(action_type, target, parameters, alert_context)
        try:
            raw  = await self._chat(system, prompt, max_tokens=600)
            data = self._extract_json(raw)
            if "commands" not in data:
                raise ValueError("Missing 'commands' key")
            return {
                "commands":       data.get("commands", []),
                "verify_command": data.get("verify_command", "echo 'no verify'"),
                "description":    data.get("description", f"Execute {action_type} on {target}"),
            }
        except Exception as exc:
            logger.error("Command generation failed for %s/%s: %s", action_type, target, exc)
            return self._fallback_commands(action_type, target, parameters)

    def _build_command_prompt(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        alert_context: Dict[str, Any],
    ) -> str:
        ctx = json.dumps({k: str(v) for k, v in alert_context.items()}, indent=2)
        return f"""Generate shell command(s) for this security response action on a Linux system.

Action: {action_type}
Target: {target}
Parameters: {json.dumps(parameters)}
Alert context: {ctx}

Rules:
- Use only standard Linux tools: ping, nmap, tcpdump, iptables, ss, whois, nslookup
- tcpdump: always use timeout (e.g. timeout 5 tcpdump -c 30 ...)
- nmap: use -F (fast) or -p <port> only, never full scan
- firewall_block: iptables -I INPUT 1 -s <ip> -j DROP
- firewall_unblock: iptables -D INPUT -s <ip> -j DROP 2>/dev/null; true
- notify: write formatted log entry to /tmp/sentinel_alerts.log

Return ONLY valid JSON (no code fences):
{{
  "commands": ["cmd1", "cmd2"],
  "verify_command": "command that confirms action succeeded (exit 0 = success)",
  "description": "one-line human description"
}}"""

    def _fallback_commands(
        self, action_type: str, target: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        fallbacks: Dict[str, Dict] = {
            "notify": {
                "commands": [
                    f"echo '[SENTINEL] ALERT: {action_type} on {target} at $(date)'"
                    " >> /tmp/sentinel_alerts.log"
                ],
                "verify_command": "test -f /tmp/sentinel_alerts.log",
                "description": f"Log alert notification for {target}",
            },
            "deep_inspect": {
                "commands": [
                    f"timeout 5 tcpdump -c 30 -n src {target} 2>&1 || "
                    f"ss -tn 'src {target}' 2>&1 || echo 'capture attempted'"
                ],
                "verify_command": "echo 'inspection complete'",
                "description": f"Capture network traffic from {target}",
            },
            "firewall_block": {
                "commands": [
                    f"iptables -C INPUT -s {target} -j DROP 2>/dev/null || "
                    f"iptables -I INPUT 1 -s {target} -j DROP"
                ],
                "verify_command": f"iptables -C INPUT -s {target} -j DROP 2>/dev/null",
                "description": f"Block all inbound traffic from {target}",
            },
            "firewall_unblock": {
                "commands": [f"iptables -D INPUT -s {target} -j DROP 2>/dev/null; true"],
                "verify_command": f"! iptables -C INPUT -s {target} -j DROP 2>/dev/null",
                "description": f"Remove firewall block for {target}",
            },
            "rate_limit": {
                "commands": [
                    f"iptables -I INPUT 1 -s {target} -m limit "
                    f"--limit 10/minute --limit-burst 20 -j ACCEPT && "
                    f"iptables -I INPUT 2 -s {target} -j DROP"
                ],
                "verify_command": f"iptables -C INPUT -s {target} -j DROP 2>/dev/null",
                "description": f"Rate-limit {target} to 10 packets/min",
            },
        }
        return fallbacks.get(action_type, {
            "commands": [
                f"echo '[SENTINEL] {action_type} on {target} at $(date)' >> /tmp/sentinel_alerts.log"
            ],
            "verify_command": "echo 'done'",
            "description": f"Execute {action_type} on {target}",
        })


# Backward-compatible alias — graph.py and execution.py import GroqClient
GroqClient = LLMClient
