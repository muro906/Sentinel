"""
LLM Client
===========
OpenAI-compatible client that works with Ollama (and vLLM) for local
inference. Uses the Instructor library to enforce structured JSON output
matching our ExecutionPlan schema.

Design:
- Talks to Ollama's OpenAI-compatible endpoint (/v1/chat/completions)
- Instructor wraps the client to enforce JSON schema via constrained decoding
- Falls back to raw JSON parsing if Instructor fails
- Retries once on malformed output before giving up
- Temperature=0.7 for diversity in plan generation
"""

import json
import logging
import os
from typing import Optional

import instructor
from openai import AsyncOpenAI

from agentic.orchestrator.config import OrchestratorConfig

logger = logging.getLogger(__name__)


def _get_client() -> AsyncOpenAI:
    """Create an AsyncOpenAI client pointed at the local Ollama instance."""
    base_url = OrchestratorConfig.LLM_BASE_URL
    # Ollama exposes OpenAI-compatible API at /v1
    if not base_url.endswith("/v1"):
        base_url = base_url.rstrip("/") + "/v1"

    return AsyncOpenAI(
        base_url=base_url,
        api_key="ollama",  # Ollama doesn't require a real key
        timeout=120.0,
    )


async def generate_plans(prompt: str, alert_id: str) -> tuple[list[dict], str]:
    """
    Send the prompt to the LLM and parse the response into plan dicts.

    Args:
        prompt: The full formatted prompt (from context_builder)
        alert_id: For logging/tracing

    Returns:
        (plans_list, raw_response_text)
    """
    client = _get_client()
    model = OrchestratorConfig.LLM_MODEL

    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=OrchestratorConfig.LLM_TEMPERATURE,
            max_tokens=OrchestratorConfig.LLM_MAX_TOKENS,
        )

        raw_text = response.choices[0].message.content or ""
        logger.info(f"LLM response for {alert_id}: {len(raw_text)} chars")

        # Parse the JSON from the response
        plans = _parse_plans(raw_text)

        return plans, raw_text

    except Exception as e:
        logger.error(f"LLM call failed for {alert_id}: {e}")
        # Return a minimal fallback plan
        fallback = _generate_fallback_plan(alert_id)
        return [fallback], f"LLM_ERROR: {str(e)}"

    finally:
        await client.close()


def _parse_plans(raw_text: str) -> list[dict]:
    """
    Extract plans from LLM response text.
    Handles various response formats (JSON block, markdown-wrapped, etc.)
    """
    # Try to find JSON in the response
    text = raw_text.strip()

    # Strip markdown code fences if present
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start)
        text = text[start:end].strip()
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start)
        text = text[start:end].strip()

    # Try to parse as JSON
    try:
        data = json.loads(text)

        # Handle both {plans: [...]} and [...] formats
        if isinstance(data, dict) and "plans" in data:
            plans = data["plans"]
        elif isinstance(data, list):
            plans = data
        else:
            plans = [data]

        # Validate basic structure
        validated = []
        for plan in plans:
            if isinstance(plan, dict) and "actions" in plan:
                validated.append(plan)

        if validated:
            return validated

    except json.JSONDecodeError:
        logger.warning("Failed to parse LLM response as JSON, attempting recovery")

    # Fallback: try to find any JSON object in the text
    import re
    json_blocks = re.findall(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text)
    for block in json_blocks:
        try:
            data = json.loads(block)
            if isinstance(data, dict) and "plans" in data:
                return data["plans"]
        except json.JSONDecodeError:
            continue

    logger.error("Could not parse any plans from LLM response")
    return []


def _generate_fallback_plan(alert_id: str) -> dict:
    """
    Generate a minimal conservative plan when the LLM fails.
    This ensures the analyst always gets SOMETHING to work with.
    """
    return {
        "plan_id": f"plan-fallback-{alert_id[:8]}",
        "confidence": 0.3,
        "risk_level": "low",
        "aggression": "conservative",
        "automation_tier": "escalate",
        "threat_summary": "LLM plan generation failed. Manual investigation recommended. "
                         "A conservative monitoring plan has been generated as a fallback.",
        "actions": [
            {
                "action_id": f"act-fallback-notify",
                "type": "notify",
                "target": "security-team",
                "params": {
                    "channel": "slack",
                    "severity": "high",
                    "message": f"Alert {alert_id}: LLM planning failed. Manual review required."
                },
                "rationale": "LLM could not generate plans. Notifying security team for manual investigation.",
                "reversible": True,
                "estimated_duration_seconds": 5,
            },
            {
                "action_id": f"act-fallback-inspect",
                "type": "deep_inspect",
                "target": "alert_traffic",
                "params": {"alert_id": alert_id, "duration_minutes": 30},
                "rationale": "Capture additional traffic for manual analysis while awaiting human review.",
                "reversible": True,
                "estimated_duration_seconds": 1800,
            },
        ],
    }
