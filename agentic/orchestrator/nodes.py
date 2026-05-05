"""
Orchestrator Graph Nodes
=========================
Each function is a node in the LangGraph state machine. Nodes receive the
current OrchestratorState, perform work, and return a partial state update.

Node pipeline:
    receive_alert → triage → dispatch_agents → await_results →
    aggregate → generate_plans → publish_plans → [await_approval] →
    [execute] → [handle_failure]

Each node emits ReasoningEvents so the SOC analyst can trace every decision.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from agentic.agents.cve_lookup import CVELookupAgent
from agentic.agents.asset_discovery import AssetDiscoveryAgent
from agentic.models.alert import AnomalyAlert
from agentic.models.reasoning import ReasoningEvent, ReasoningEventType
from agentic.models.threat_bundle import ThreatBundle, HistoricalIncident
from agentic.orchestrator.config import OrchestratorConfig
from agentic.orchestrator.state import OrchestratorState
from agentic.reasoning.emitter import emit_reasoning_event
from agentic.state import session, result_store
from agentic.db import incident_repository

logger = logging.getLogger(__name__)

# Instantiate sub-agents (singleton, stateless)
cve_agent = CVELookupAgent(
    timeout_seconds=OrchestratorConfig.AGENT_TIMEOUT_SECONDS,
    max_retries=OrchestratorConfig.AGENT_MAX_RETRIES,
)
asset_agent = AssetDiscoveryAgent(
    timeout_seconds=OrchestratorConfig.AGENT_TIMEOUT_SECONDS,
    max_retries=OrchestratorConfig.AGENT_MAX_RETRIES,
)


async def receive_alert(state: OrchestratorState) -> dict:
    """
    Node 1: Parse and validate the incoming alert from Kafka.
    Extracts key fields into the state for downstream nodes.
    """
    alert_raw = state["alert_raw"]
    alert = AnomalyAlert(**alert_raw)
    fv = alert.feature_vector

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert.alert_id,
        event_type=ReasoningEventType.ALERT_RECEIVED,
        agent="orchestrator",
        action=f"Received anomaly alert: {alert.classification} (score={alert.anomaly_score:.2f})",
        input_summary=f"src={fv.src_ip}:{fv.src_port} → dst={fv.dst_ip}:{fv.dst_port} [{fv.proto}]",
        output_summary=f"Classification: {alert.classification}, Score: {alert.anomaly_score:.2f}",
        full_input=alert_raw,
        rationale=f"Alert {alert.alert_id} received from anomaly-alerts topic. "
                  f"Ensemble classified traffic as '{alert.classification}' with {alert.anomaly_score:.0%} confidence. "
                  f"Proceeding to triage.",
    ))

    # Create session in Redis
    await session.create_session(alert.alert_id, {
        "classification": alert.classification,
        "anomaly_score": str(alert.anomaly_score),
        "src_ip": fv.src_ip,
        "dst_ip": fv.dst_ip,
    })

    # Create incident record in PostgreSQL
    try:
        await incident_repository.create_incident(
            alert_id=alert.alert_id,
            classification=alert.classification,
            anomaly_score=alert.anomaly_score,
            src_ip=fv.src_ip,
            dst_ip=fv.dst_ip,
            dst_port=fv.dst_port,
            priority="pending",
            feature_vector=alert_raw.get("feature_vector", {}),
        )
    except Exception as e:
        logger.warning(f"Failed to create incident record: {e}")

    return {
        "alert_id": alert.alert_id,
        "alert_timestamp": alert.timestamp.isoformat(),
        "classification": alert.classification,
        "anomaly_score": alert.anomaly_score,
        "src_ip": fv.src_ip,
        "dst_ip": fv.dst_ip,
        "dst_port": fv.dst_port,
        "current_node": "receive_alert",
    }


async def triage(state: OrchestratorState) -> dict:
    """
    Node 2: Triage the alert — compute priority and check for duplicates.

    Priority formula:
        priority_score = anomaly_score × (6 - asset_criticality_guess) × classification_weight

    Deduplication:
        Skip if same classification + src_ip seen within 5-minute window.
    """
    alert_id = state["alert_id"]
    classification = state["classification"]
    src_ip = state["src_ip"]
    anomaly_score = state["anomaly_score"]

    # Check deduplication
    is_dup = await session.check_duplicate(classification, src_ip)
    if is_dup:
        await emit_reasoning_event(ReasoningEvent(
            alert_id=alert_id,
            event_type=ReasoningEventType.DUPLICATE_DETECTED,
            agent="orchestrator",
            action=f"Duplicate detected: {classification} from {src_ip}",
            rationale=f"An alert with classification '{classification}' from source {src_ip} "
                      f"was already processed within the last {OrchestratorConfig.DEDUP_WINDOW_SECONDS}s. "
                      f"Skipping to avoid duplicate investigation.",
        ))
        return {"is_duplicate": True, "current_node": "triage"}

    # Mark as seen for deduplication window
    await session.mark_seen(classification, src_ip, alert_id)

    # Classification weights (how severe is this attack type?)
    classification_weights = {
        "exploit_attempt": 2.0, "privilege_escalation": 1.8,
        "lateral_movement": 1.7, "c2_communication": 1.6,
        "data_exfiltration": 1.5, "brute_force": 1.2,
        "dns_tunneling": 1.1, "port_scan": 0.8,
        "unknown": 1.0,
    }
    class_weight = classification_weights.get(classification, 1.0)

    # Priority score (higher = more urgent)
    priority_score = anomaly_score * class_weight * 5.0  # scale to ~0-10

    # Map to priority label
    if priority_score >= OrchestratorConfig.PRIORITY_CRITICAL_THRESHOLD:
        priority = "critical"
    elif priority_score >= OrchestratorConfig.PRIORITY_HIGH_THRESHOLD:
        priority = "high"
    elif priority_score >= OrchestratorConfig.PRIORITY_MEDIUM_THRESHOLD:
        priority = "medium"
    else:
        priority = "low"

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert_id,
        event_type=ReasoningEventType.TRIAGE_DECISION,
        agent="orchestrator",
        action=f"Triaged alert as {priority.upper()} priority (score={priority_score:.2f})",
        input_summary=f"anomaly_score={anomaly_score:.2f}, class={classification}, weight={class_weight}",
        output_summary=f"Priority: {priority}, Score: {priority_score:.2f}",
        rationale=f"Priority computed: anomaly_score({anomaly_score:.2f}) × "
                  f"class_weight({class_weight}) × 5.0 = {priority_score:.2f}. "
                  f"Classification '{classification}' has weight {class_weight} "
                  f"({'high severity' if class_weight > 1.3 else 'moderate severity'}). "
                  f"Mapped to '{priority}' priority tier. Proceeding to agent dispatch.",
        confidence=min(anomaly_score, 1.0),
    ))

    await session.update_session(alert_id, {
        "state": "triaged",
        "priority": priority,
        "triaged_at": str(time.time()),
    })

    return {
        "priority": priority,
        "priority_score": priority_score,
        "is_duplicate": False,
        "current_node": "triage",
    }


async def dispatch_agents(state: OrchestratorState) -> dict:
    """
    Node 3: Dispatch sub-agents in parallel with timeout.

    Sends tasks to CVE Lookup Agent and Asset Discovery Agent simultaneously
    using asyncio.gather. If either times out, proceeds with partial results.
    """
    alert_id = state["alert_id"]

    # Build task data from state (shared by both agents)
    task_data = {
        "alert_id": alert_id,
        "src_ip": state.get("src_ip"),
        "dst_ip": state.get("dst_ip"),
        "dst_port": state.get("dst_port"),
        "classification": state.get("classification"),
        "anomaly_score": state.get("anomaly_score"),
    }

    # Extract feature-specific fields from the raw alert
    alert_raw = state.get("alert_raw", {})
    fv = alert_raw.get("feature_vector", {})
    task_data.update({
        "proto": fv.get("proto"),
        "conn_state": fv.get("conn_state"),
        "service": fv.get("service"),
        "ssl_version": fv.get("ssl_version"),
        "dns_query": fv.get("dns_query"),
        "bytes_ratio": fv.get("bytes_ratio", 0),
        "is_dns": fv.get("is_dns", 0),
    })

    agents_dispatched = ["cve_lookup", "asset_discovery"]

    # Dispatch both agents in parallel
    start_time = time.time()
    cve_result, asset_result = await asyncio.gather(
        cve_agent.execute(alert_id, task_data),
        asset_agent.execute(alert_id, task_data),
        return_exceptions=True,
    )

    duration_ms = int((time.time() - start_time) * 1000)

    # Process results
    agents_completed = []
    agents_timed_out = []
    cve_matches = []
    affected_assets = []
    source_context = None
    target_context = None

    # Handle CVE results
    if isinstance(cve_result, Exception):
        agents_timed_out.append("cve_lookup")
        logger.error(f"CVE agent exception: {cve_result}")
    elif cve_result.get("_error"):
        agents_timed_out.append("cve_lookup")
    else:
        agents_completed.append("cve_lookup")
        cve_matches = cve_result.get("matches", [])

    # Handle Asset results
    if isinstance(asset_result, Exception):
        agents_timed_out.append("asset_discovery")
        logger.error(f"Asset agent exception: {asset_result}")
    elif asset_result.get("_error"):
        agents_timed_out.append("asset_discovery")
    else:
        agents_completed.append("asset_discovery")
        affected_assets = asset_result.get("affected_assets", [])
        source_context = asset_result.get("source_context")
        target_context = asset_result.get("target_context")

    # Store results in Redis for persistence
    if cve_matches:
        await result_store.store_result(alert_id, "cve_lookup", cve_matches)
    if affected_assets:
        await result_store.store_result(alert_id, "asset_discovery", affected_assets)

    logger.info(
        f"Agents completed in {duration_ms}ms. "
        f"Completed: {agents_completed}, Timed out: {agents_timed_out}"
    )

    return {
        "cve_matches": cve_matches,
        "affected_assets": affected_assets,
        "source_context": source_context,
        "target_context": target_context,
        "agents_dispatched": agents_dispatched,
        "agents_completed": agents_completed,
        "agents_timed_out": agents_timed_out,
        "current_node": "dispatch_agents",
    }


async def aggregate(state: OrchestratorState) -> dict:
    """
    Node 4: Aggregate sub-agent results into a ThreatBundle.

    Merges CVE matches + asset info + original alert into a single enriched
    context object. Computes risk metadata (max CVSS, blast radius, etc.)
    and queries historical incidents for LLM few-shot context.
    """
    alert_id = state["alert_id"]
    alert_raw = state.get("alert_raw", {})

    # Build the ThreatBundle
    alert_model = AnomalyAlert(**alert_raw)

    from agentic.models.cve import CVEMatch
    from agentic.models.asset import AssetInfo

    cve_matches_models = []
    for cm in state.get("cve_matches", []):
        try:
            cve_matches_models.append(CVEMatch(**cm))
        except Exception as e:
            logger.warning(f"Failed to parse CVEMatch: {e}")

    asset_models = []
    for ai in state.get("affected_assets", []):
        try:
            asset_models.append(AssetInfo(**ai))
        except Exception as e:
            logger.warning(f"Failed to parse AssetInfo: {e}")

    # Query historical incidents for LLM few-shot context
    similar_incidents = []
    try:
        hist_records = await incident_repository.find_similar_incidents(
            classification=state.get("classification", ""),
            dst_port=state.get("dst_port"),
            limit=3,
        )
        for rec in hist_records:
            similar_incidents.append(HistoricalIncident(
                alert_id=rec.get("alert_id", ""),
                timestamp=rec.get("received_at", ""),
                classification=rec.get("classification", ""),
                anomaly_score=rec.get("anomaly_score", 0),
                outcome=rec.get("outcome", "unknown"),
                actions_taken=[a.get("type", "?") for a in (rec.get("execution_results") or [])],
            ))
    except Exception as e:
        logger.warning(f"Failed to query historical incidents: {e}")

    bundle = ThreatBundle(
        alert=alert_model,
        cve_matches=cve_matches_models,
        affected_assets=asset_models,
        similar_incidents=similar_incidents,
    )
    bundle.compute_risk_metadata()

    bundle_dict = bundle.model_dump(mode="json")

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert_id,
        event_type=ReasoningEventType.CONTEXT_BUILT,
        agent="orchestrator",
        action="Aggregated sub-agent results into ThreatBundle",
        input_summary=f"{len(cve_matches_models)} CVEs, {len(asset_models)} assets",
        output_summary=f"Priority: {bundle.priority}, Max CVSS: {bundle.max_cvss}, "
                       f"Blast radius: {bundle.total_blast_radius:.1f}, "
                       f"Active exploit: {bundle.has_active_exploit}",
        full_output={"priority": bundle.priority, "max_cvss": bundle.max_cvss,
                     "total_blast_radius": bundle.total_blast_radius,
                     "has_active_exploit": bundle.has_active_exploit},
        rationale=f"Merged {len(cve_matches_models)} CVE matches and {len(asset_models)} affected assets "
                  f"with the original alert into a ThreatBundle. "
                  f"Computed risk metadata: priority={bundle.priority}, max_cvss={bundle.max_cvss}, "
                  f"blast_radius={bundle.total_blast_radius:.1f}. "
                  f"{'CRITICAL: Active exploit detected for matched CVE.' if bundle.has_active_exploit else ''} "
                  f"Passing to Planning Agent for execution plan generation.",
    ))

    await session.update_session(alert_id, {"state": "aggregated"})

    return {
        "threat_bundle": bundle_dict,
        "priority": bundle.priority,
        "max_cvss": bundle.max_cvss,
        "max_asset_criticality": bundle.max_asset_criticality,
        "total_blast_radius": bundle.total_blast_radius,
        "has_active_exploit": bundle.has_active_exploit,
        "current_node": "aggregate",
    }


async def generate_plans(state: OrchestratorState) -> dict:
    """
    Node 5: Invoke the Planning Agent (LLM) to generate execution plans.

    Builds a structured prompt from the ThreatBundle, sends to the LLM,
    parses structured output into ExecutionPlans, and ranks them.
    """
    alert_id = state["alert_id"]

    # Import planning components
    from agentic.planning.context_builder import build_prompt
    from agentic.planning.llm_client import generate_plans as llm_generate
    from agentic.planning.plan_ranker import rank_plans

    threat_bundle = state.get("threat_bundle", {})

    # Build the LLM prompt
    prompt = build_prompt(threat_bundle)

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert_id,
        event_type=ReasoningEventType.LLM_PROMPT,
        agent="planning",
        action="Built prompt for LLM plan generation",
        input_summary=f"ThreatBundle: priority={threat_bundle.get('priority')}, "
                      f"max_cvss={threat_bundle.get('max_cvss')}",
        output_summary=f"Prompt length: {len(prompt)} chars",
        full_input={"prompt_text": prompt},
        rationale="Assembled structured prompt from ThreatBundle context including alert details, "
                  "CVE matches, affected assets, and risk metadata. Sending to LLM for plan generation.",
    ))

    # Call the LLM
    start_time = time.time()
    raw_plans, raw_response = await llm_generate(prompt, alert_id)
    duration_ms = int((time.time() - start_time) * 1000)

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert_id,
        event_type=ReasoningEventType.LLM_RESPONSE,
        agent="planning",
        action=f"LLM generated {len(raw_plans)} execution plans in {duration_ms}ms",
        input_summary=f"Prompt: {len(prompt)} chars",
        output_summary=f"{len(raw_plans)} plans generated",
        full_input={"prompt_text": prompt},
        full_output={"raw_response": raw_response, "parsed_plans": raw_plans},
        rationale=f"LLM returned {len(raw_plans)} plans in {duration_ms}ms. "
                  f"Plans cover different aggression levels. Proceeding to scoring and ranking.",
        duration_ms=duration_ms,
    ))

    # Rank plans
    ranked_plans = rank_plans(raw_plans, state)

    # Build PlanSet
    plan_set = {
        "alert_id": alert_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threat_summary": threat_bundle.get("priority", "unknown") + " priority threat",
        "plans": ranked_plans,
        "cve_matches": state.get("cve_matches", []),
        "affected_assets": state.get("affected_assets", []),
    }

    best_confidence = max((p.get("confidence", 0) for p in ranked_plans), default=0)

    for plan in ranked_plans:
        await emit_reasoning_event(ReasoningEvent(
            alert_id=alert_id,
            event_type=ReasoningEventType.PLAN_SCORED,
            agent="planning",
            action=f"Plan '{plan.get('aggression', '?')}' scored: "
                   f"confidence={plan.get('confidence', 0):.2f}, risk={plan.get('risk_level', '?')}",
            output_summary=f"{len(plan.get('actions', []))} actions, tier={plan.get('automation_tier', '?')}",
            full_output=plan,
            rationale=f"Plan with {plan.get('aggression', '?')} aggression: "
                      f"confidence={plan.get('confidence', 0):.2f}, "
                      f"risk_level={plan.get('risk_level', '?')}, "
                      f"automation_tier={plan.get('automation_tier', '?')}. "
                      f"Contains {len(plan.get('actions', []))} actions.",
            confidence=plan.get("confidence", 0),
        ))

    await session.update_session(alert_id, {
        "state": "plans_generated",
        "plans_ready_at": str(time.time()),
    })

    return {
        "plans": ranked_plans,
        "plan_set": plan_set,
        "llm_prompt": prompt,
        "llm_response": raw_response,
        "best_plan_confidence": best_confidence,
        "current_node": "generate_plans",
    }


async def publish_plans(state: OrchestratorState) -> dict:
    """
    Node 6: Publish the PlanSet to Kafka for the SOC dashboard.
    Also determines the automation tier (how much human involvement needed).
    """
    alert_id = state["alert_id"]
    plan_set = state.get("plan_set", {})
    best_confidence = state.get("best_plan_confidence", 0)

    automation_tier = OrchestratorConfig.get_automation_tier(best_confidence)

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert_id,
        event_type=ReasoningEventType.PLAN_PUBLISHED,
        agent="orchestrator",
        action=f"Published {len(plan_set.get('plans', []))} plans to dashboard. "
               f"Automation tier: {automation_tier}",
        output_summary=f"Best confidence: {best_confidence:.2f}, Tier: {automation_tier}",
        rationale=f"Best plan confidence ({best_confidence:.2f}) maps to automation tier '{automation_tier}'. "
                  + {
                      "auto_execute": "Confidence >= 95%: system can execute without human approval.",
                      "auto_recommend": "Confidence >= 85%: recommended to analyst with pre-selected approval.",
                      "suggest": "Confidence >= 70%: suggested plan, analyst reviews before approval.",
                      "advise": "Confidence >= 50%: advisory only, analyst makes all decisions.",
                      "escalate": "Confidence < 50%: escalating to senior analyst for manual assessment.",
                  }.get(automation_tier, "Unknown tier."),
        confidence=best_confidence,
    ))

    # Publish to Kafka (the dashboard consumes this)
    from agentic.kafka.producer import PlanProducer
    from agentic.models.plan import PlanSet as PlanSetModel

    try:
        plan_set_model = PlanSetModel(**plan_set)
        producer = PlanProducer()
        producer.connect()
        producer.publish_plans(plan_set_model)
        producer.close()
    except Exception as e:
        logger.error(f"Failed to publish plans to Kafka: {e}")

    return {
        "approval_status": "pending",
        "current_node": "publish_plans",
    }


async def handle_failure(state: OrchestratorState) -> dict:
    """
    Node 7: Handle execution failures — trigger re-planning if needed.
    """
    alert_id = state["alert_id"]
    failed = state.get("failed_actions", [])

    await emit_reasoning_event(ReasoningEvent(
        alert_id=alert_id,
        event_type=ReasoningEventType.REPLAN_TRIGGERED,
        agent="orchestrator",
        action=f"Re-planning triggered: {len(failed)} action(s) failed",
        input_summary=f"Failed: {[a.get('type', '?') for a in failed]}",
        rationale=f"{len(failed)} actions failed during execution. "
                  f"Triggering re-planning with failure context to generate alternative approach.",
    ))

    return {
        "should_replan": True,
        "current_node": "handle_failure",
    }


# ── Routing Functions ──────────────────────────────────────────────────────────

def should_continue_after_triage(state: OrchestratorState) -> str:
    """After triage: skip if duplicate or below threshold, else dispatch agents."""
    if state.get("is_duplicate"):
        return "end"
    if state.get("anomaly_score", 0) < OrchestratorConfig.MIN_ANOMALY_SCORE:
        return "end"
    return "dispatch_agents"


def should_replan_or_end(state: OrchestratorState) -> str:
    """After execution results: re-plan on failure, or end."""
    if state.get("should_replan"):
        return "generate_plans"
    return "end"
