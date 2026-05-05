"""
Orchestrator State (TypedDict)
===============================
Defines the shared state object that flows through the LangGraph state machine.
Every node reads from and writes to this state — it is the single source of
truth for the orchestrator's progress on a given alert.

LangGraph passes this TypedDict between nodes. Each node can read any field
and return a partial dict to update specific fields. LangGraph merges the
updates into the running state automatically.

The state captures the full incident lifecycle:
    receive → triage → dispatch → await → aggregate → plan → publish → approve → execute
"""

from typing import Optional, Literal, TypedDict


class OrchestratorState(TypedDict, total=False):
    """
    Full state for one alert flowing through the LangGraph orchestrator.

    Fields are grouped by lifecycle stage. total=False means all fields
    are optional (nodes only set the fields they're responsible for).
    """

    # ── Alert Input ────────────────────────────────────────────────────────────
    alert_id: str                         # unique alert identifier
    alert_raw: dict                       # raw alert JSON from Kafka
    alert_timestamp: str                  # when the alert was detected

    # ── Triage ─────────────────────────────────────────────────────────────────
    classification: str                   # attack type (port_scan, etc.)
    anomaly_score: float                  # ensemble score (0-1)
    src_ip: str                           # source IP
    dst_ip: str                           # destination IP
    dst_port: int                         # target port
    priority: str                         # computed priority (low/medium/high/critical)
    priority_score: float                 # numerical priority score
    is_duplicate: bool                    # deduplication check result

    # ── Sub-Agent Results ──────────────────────────────────────────────────────
    cve_matches: list[dict]               # CVE Lookup Agent results
    affected_assets: list[dict]           # Asset Discovery Agent results
    source_context: Optional[dict]        # context about the source IP
    target_context: Optional[dict]        # context about the target IP
    agents_dispatched: list[str]          # which agents were dispatched
    agents_completed: list[str]           # which agents returned results
    agents_timed_out: list[str]           # which agents timed out

    # ── Threat Bundle (aggregated) ─────────────────────────────────────────────
    threat_bundle: dict                   # complete enriched context
    max_cvss: float                       # highest CVSS among matched CVEs
    max_asset_criticality: int            # most critical asset tier (1=highest)
    total_blast_radius: float             # sum of all affected assets' blast radius
    has_active_exploit: bool              # any CVE has known exploit?

    # ── Planning ───────────────────────────────────────────────────────────────
    llm_prompt: str                       # the prompt sent to the LLM
    llm_response: str                     # raw LLM response text
    plans: list[dict]                     # generated execution plans
    plan_set: dict                        # full PlanSet with metadata
    best_plan_confidence: float           # confidence of the top-ranked plan

    # ── Approval ───────────────────────────────────────────────────────────────
    approval_status: str                  # pending, approved, rejected, timeout
    approved_plan_id: Optional[str]       # which plan was approved
    approved_actions: list[dict]          # actions to execute (possibly modified)
    approved_by: Optional[str]            # analyst who approved
    approval_notes: Optional[str]         # analyst comments

    # ── Execution ──────────────────────────────────────────────────────────────
    execution_results: list[dict]         # results from execution layer
    execution_status: str                 # pending, executing, completed, failed
    failed_actions: list[dict]            # actions that failed

    # ── Control Flow ───────────────────────────────────────────────────────────
    current_node: str                     # tracks where we are in the graph
    error: Optional[str]                  # error message if something broke
    should_replan: bool                   # trigger re-planning after failure
