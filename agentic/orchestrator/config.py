"""
Orchestrator Configuration
===========================
Centralized thresholds, timeouts, and feature flags for the orchestrator.
All values can be overridden via environment variables for deployment flexibility.
"""

import os


class OrchestratorConfig:
    """Configuration for the orchestrator state machine."""

    # ── Agent Timeouts ─────────────────────────────────────────────────────────
    AGENT_TIMEOUT_SECONDS: float = float(os.environ.get("AGENT_TIMEOUT", "30"))
    AGENT_MAX_RETRIES: int = int(os.environ.get("AGENT_MAX_RETRIES", "2"))

    # ── Triage Thresholds ──────────────────────────────────────────────────────
    # Anomaly score below this is dropped (too low confidence)
    MIN_ANOMALY_SCORE: float = float(os.environ.get("MIN_ANOMALY_SCORE", "0.5"))

    # Priority thresholds (priority_score ranges)
    PRIORITY_CRITICAL_THRESHOLD: float = 8.0
    PRIORITY_HIGH_THRESHOLD: float = 5.0
    PRIORITY_MEDIUM_THRESHOLD: float = 2.5

    # ── Deduplication ──────────────────────────────────────────────────────────
    DEDUP_WINDOW_SECONDS: int = int(os.environ.get("DEDUP_WINDOW", "300"))

    # ── Planning ───────────────────────────────────────────────────────────────
    NUM_PLANS_TO_GENERATE: int = int(os.environ.get("NUM_PLANS", "3"))
    LLM_TEMPERATURE: float = float(os.environ.get("LLM_TEMPERATURE", "0.7"))
    LLM_MAX_TOKENS: int = int(os.environ.get("LLM_MAX_TOKENS", "2048"))

    # ── Automation Tiers ───────────────────────────────────────────────────────
    # Confidence thresholds that determine how much human involvement is needed
    AUTO_EXECUTE_THRESHOLD: float = 0.95   # fully automatic (very high confidence)
    AUTO_RECOMMEND_THRESHOLD: float = 0.85  # auto-recommend, human confirms
    SUGGEST_THRESHOLD: float = 0.70         # suggest plan, human reviews
    ADVISE_THRESHOLD: float = 0.50          # advise only, human decides
    # Below ADVISE_THRESHOLD → escalate to senior analyst

    # ── Approval ───────────────────────────────────────────────────────────────
    APPROVAL_TIMEOUT_SECONDS: int = int(os.environ.get("APPROVAL_TIMEOUT", "600"))
    ESCALATION_ON_TIMEOUT: bool = True

    # ── LLM ────────────────────────────────────────────────────────────────────
    LLM_BASE_URL: str = os.environ.get("LLM_BASE_URL", "https://api.groq.com/openai/v1")
    LLM_MODEL: str = os.environ.get("LLM_MODEL", "llama-3.1-8b-instant")
    GROQ_API_KEY: str = os.environ.get("GROQ_API_KEY", "")

    @classmethod
    def get_automation_tier(cls, confidence: float) -> str:
        """Map confidence score to automation tier."""
        if confidence >= cls.AUTO_EXECUTE_THRESHOLD:
            return "auto_execute"
        elif confidence >= cls.AUTO_RECOMMEND_THRESHOLD:
            return "auto_recommend"
        elif confidence >= cls.SUGGEST_THRESHOLD:
            return "suggest"
        elif confidence >= cls.ADVISE_THRESHOLD:
            return "advise"
        else:
            return "escalate"
