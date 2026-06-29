"""LangGraph orchestrator — ingestion graph + investigation graph.

Two graphs handle the full alert lifecycle:
  - Ingestion graph:     receive_alert  → END
  - Investigation graph: dispatch_agents → generate_plans → publish_plans → END
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import TypedDict

import asyncpg
from langgraph.graph import StateGraph, END

from agents.asset_discovery import AssetDiscoveryAgent
from agents.cve_lookup import CVELookupAgent
from llm_client import GroqClient
from kafka.producer import PlanProducer
from reasoning import emit_trace

logger = logging.getLogger(__name__)

DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel")

# ---------------------------------------------------------------------------
# Shared state schema
# ---------------------------------------------------------------------------

class GraphState(TypedDict):
    """Typed dict that flows through every LangGraph node.

    Fields are populated incrementally as each node runs:
      - receive_alert     fills classification, src/dst_ip, dst_port, anomaly_score
      - dispatch_agents   fills asset_context, cve_matches
      - generate_plans    fills plans
      - publish_plans     updates status to 'published'
    """
    alert_id:       str
    alert_raw:      dict
    classification: str
    src_ip:         str
    dst_ip:         str
    dst_port:       int
    anomaly_score:  float
    asset_context:  dict
    cve_matches:    list
    plans:          list
    status:         str
    error:          str
    replan_context: str


# ---------------------------------------------------------------------------
# Module-level singletons — instantiated once, reused across all invocations
# ---------------------------------------------------------------------------

_asset_agent   = AssetDiscoveryAgent()
_cve_agent     = CVELookupAgent()
_llm_client    = GroqClient()
_plan_producer = PlanProducer()

# Lazy asyncpg connection pool — created on first DB call, shared thereafter.
# Avoids the overhead of opening a new TCP connection for every DB operation.
_pool: asyncpg.Pool | None = None


async def _get_pool() -> asyncpg.Pool:
    """Return the shared connection pool, initialising it on first call."""
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
    return _pool


# ---------------------------------------------------------------------------
# Graph node functions
# ---------------------------------------------------------------------------

async def receive_alert(state: GraphState) -> GraphState:
    """Node 1 (ingestion graph): parse the raw alert payload and persist the incident.

    Extracts the feature vector fields (IPs, port, protocol) and the top-level
    anomaly_score / classification, then writes a new incident row if one does
    not already exist.  Returns an updated state with the parsed fields.
    """
    logger.info("Node[receive_alert]: %s", state["alert_id"])
    raw = state["alert_raw"]
    fv  = raw.get("feature_vector", {})

    await _ensure_incident_exists(state["alert_id"], raw, fv)
    await emit_trace(
        alert_id=state["alert_id"], event_type="alert_received", agent="orchestrator",
        action=f"Received alert: {raw.get('classification', 'unknown')}",
        input_summary=(
            f"src={fv.get('src_ip')}:{fv.get('src_port')} "
            f"dst={fv.get('dst_ip')}:{fv.get('dst_port')} [{fv.get('proto')}]"
        ),
        output_summary=f"score={raw.get('anomaly_score', 0):.2f}",
        rationale="Alert received from detection layer. Stored as received.",
    )
    return {
        **state,
        "classification": raw.get("classification", "unknown"),
        "src_ip":        str(fv.get("src_ip", "")),
        "dst_ip":        str(fv.get("dst_ip", "")),
        "dst_port":      int(fv.get("dst_port", 0)),
        "anomaly_score": float(raw.get("anomaly_score", 0)),
        "status": "received",
    }


async def dispatch_agents(state: GraphState) -> GraphState:
    """Node 1 (investigation graph): run asset discovery and CVE lookup concurrently.

    Both sub-agents are awaited with asyncio.gather so they execute in parallel,
    cutting total enrichment latency roughly in half compared to sequential calls.
    Partial failures are tolerated: a failed agent logs an error trace and
    contributes an empty result so the pipeline can still proceed.
    """
    alert_id = state["alert_id"]
    logger.info("Node[dispatch_agents]: %s", alert_id)
    await emit_trace(
        alert_id=alert_id, event_type="agent_dispatched", agent="orchestrator",
        action="Dispatching asset_discovery and cve_lookup in parallel",
        rationale="Enriching alert with network context and vulnerability data.",
    )

    t0 = datetime.now(timezone.utc)
    asset_ctx, cve_matches = await asyncio.gather(
        _asset_agent.discover(state["src_ip"], state["dst_ip"], state["dst_port"]),
        _cve_agent.lookup(state["dst_port"], None, state["classification"]),
        return_exceptions=True,  # prevents one failure from cancelling the other
    )
    dur = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

    # Degrade gracefully: replace exceptions with empty defaults and emit error traces.
    if isinstance(asset_ctx, Exception):
        await emit_trace(alert_id=alert_id, event_type="agent_error", agent="asset_discovery",
                         action="Asset discovery failed", rationale=str(asset_ctx),
                         error=str(asset_ctx), duration_ms=dur)
        asset_ctx = {}
    if isinstance(cve_matches, Exception):
        await emit_trace(alert_id=alert_id, event_type="agent_error", agent="cve_lookup",
                         action="CVE lookup failed", rationale=str(cve_matches),
                         error=str(cve_matches), duration_ms=dur)
        cve_matches = []

    await _store_enrichment(alert_id, asset_ctx, cve_matches)
    await emit_trace(
        alert_id=alert_id, event_type="agent_result", agent="orchestrator",
        action="Context agents completed",
        output_summary=f"open_ports={asset_ctx.get('open_ports', [])} cves={len(cve_matches)}",
        rationale=f"{len(cve_matches)} CVEs found, asset reachable={asset_ctx.get('dst_reachable')}.",
        duration_ms=dur,
    )
    return {**state, "asset_context": asset_ctx, "cve_matches": cve_matches, "status": "agents_complete"}


async def generate_plans(state: GraphState) -> GraphState:
    """Node 2 (investigation graph): call the LLM to produce ranked remediation plans.

    Passes the full alert context (classification, asset data, CVEs) to the Groq
    client.  When this node is re-entered after a failed execution attempt the
    replan_context field is appended to the prompt so the LLM can avoid
    previously-failed action sequences.  Each plan is traced individually so the
    dashboard can show per-plan confidence and risk scores.
    """
    alert_id = state["alert_id"]
    logger.info("Node[generate_plans]: %s", alert_id)
    replan_note = state.get("replan_context", "")

    await emit_trace(
        alert_id=alert_id, event_type="llm_prompt", agent="planning",
        action="Building LLM prompt for plan generation",
        input_summary=(
            f"classification={state['classification']} cves={len(state.get('cve_matches', []))}"
            + (f" replan={replan_note[:60]}" if replan_note else "")
        ),
        rationale="Assembling prompt from alert, assets, CVEs" +
                  (" and prior plan failure context." if replan_note else "."),
    )

    # Inject replan note into a copy of the raw alert so the LLM sees it.
    alert_raw = dict(state["alert_raw"])
    if replan_note:
        alert_raw["replan_note"] = replan_note

    try:
        t0 = datetime.now(timezone.utc)
        plans = await _llm_client.generate_plans(alert_raw, state["asset_context"], state["cve_matches"])
        dur = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        await emit_trace(
            alert_id=alert_id, event_type="llm_response", agent="planning",
            action=f"LLM generated {len(plans)} plans in {dur}ms",
            full_output={"plans": plans},
            rationale="Plans generated covering different aggression tiers.",
            duration_ms=dur,
        )
        # Emit a scored trace for each plan so the UI can render per-plan metadata.
        for idx, plan in enumerate(plans):
            await emit_trace(
                alert_id=alert_id, event_type="plan_scored", agent="planning",
                action=f"Plan '{plan.get('automation_tier', '?')}' evaluated",
                output_summary=f"{len(plan.get('actions', []))} actions",
                full_output=plan,
                rationale=(
                    f"Plan {idx + 1}: confidence={plan.get('confidence', 0):.2f} "
                    f"risk={plan.get('risk_level', '?')}"
                ),
                confidence=plan.get("confidence"),
            )
        return {**state, "plans": plans, "status": "plans_generated"}

    except Exception as e:
        logger.error("Plan generation failed: %s", e)
        await emit_trace(alert_id=alert_id, event_type="agent_error", agent="planning",
                         action="Plan generation failed", rationale=str(e), error=str(e))
        return {**state, "plans": [], "error": str(e), "status": "plan_generation_failed"}


async def publish_plans(state: GraphState) -> GraphState:
    """Node 3 (investigation graph): send plans to Kafka for the dashboard to consume.

    The Kafka message bundles the plans alongside a metadata envelope that includes
    the asset context, CVE matches, and generation timestamp so consumers have full
    context without a separate DB lookup.  connect/close wraps every publish to
    avoid holding an idle Kafka connection between potentially long-running graph
    runs.
    """
    alert_id = state["alert_id"]
    logger.info("Node[publish_plans]: %s", alert_id)
    try:
        _plan_producer.connect()
        try:
            _plan_producer.publish_plans(
                alert_id, state["plans"],
                {
                    "asset_context":  state["asset_context"],
                    "cve_matches":    state["cve_matches"],
                    "generated_at":   datetime.now(timezone.utc).isoformat(),
                },
            )
        finally:
            # Always close so the Kafka connection is not leaked on publish errors.
            _plan_producer.close()

        best_conf = max((p.get("confidence", 0) for p in state["plans"]), default=0)
        await emit_trace(
            alert_id=alert_id, event_type="plan_published", agent="orchestrator",
            action=f"Published {len(state['plans'])} plans to dashboard",
            output_summary=f"best_confidence={best_conf:.2f}",
            rationale="Plans sent via Kafka; backend will store and broadcast to frontend.",
        )
        return {**state, "status": "published"}

    except Exception as e:
        logger.error("Plan publication failed: %s", e)
        await emit_trace(alert_id=alert_id, event_type="agent_error", agent="orchestrator",
                         action="Plan publication failed", rationale=str(e), error=str(e))
        return {**state, "error": str(e), "status": "publication_failed"}


# ---------------------------------------------------------------------------
# Graph builders — compiled once per process via lru_cache
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def build_ingestion_graph():
    """Compile and return the single-node ingestion graph.

    Cached with lru_cache so StateGraph.compile() (which builds the Pregel
    execution plan) only runs once per process, not once per alert.
    """
    g = StateGraph(GraphState)
    g.add_node("receive_alert", receive_alert)
    g.set_entry_point("receive_alert")
    g.add_edge("receive_alert", END)
    return g.compile()


@lru_cache(maxsize=1)
def build_investigation_graph():
    """Compile and return the three-node investigation graph.

    Nodes execute sequentially: dispatch_agents → generate_plans → publish_plans.
    Cached for the same reason as build_ingestion_graph.
    """
    g = StateGraph(GraphState)
    g.add_node("dispatch_agents", dispatch_agents)
    g.add_node("generate_plans",  generate_plans)
    g.add_node("publish_plans",   publish_plans)
    g.set_entry_point("dispatch_agents")
    g.add_edge("dispatch_agents", "generate_plans")
    g.add_edge("generate_plans",  "publish_plans")
    g.add_edge("publish_plans",   END)
    return g.compile()


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

async def process_alert(alert_data: dict) -> dict:
    """Run the ingestion graph for a freshly-arrived alert.

    Builds the initial GraphState from the raw Kafka message payload and invokes
    the ingestion graph, which stores the incident and emits a receipt trace.
    Returns the final graph state dict.
    """
    fv = alert_data.get("feature_vector", {})
    state: GraphState = {
        "alert_id":      alert_data.get("alert_id", "unknown"),
        "alert_raw":     alert_data,
        "classification": "",
        "src_ip":        str(fv.get("src_ip", "")),
        "dst_ip":        str(fv.get("dst_ip", "")),
        "dst_port":      int(fv.get("dst_port", 0)),
        "anomaly_score": float(alert_data.get("anomaly_score", 0)),
        "asset_context": {}, "cve_matches": [], "plans": [],
        "status": "initialized", "error": "", "replan_context": "",
    }
    return await build_ingestion_graph().ainvoke(state)


async def process_investigation(alert_id: str, replan_context: str = "") -> dict:
    """Run the investigation graph for an already-ingested alert.

    Fetches the stored incident from PostgreSQL, reconstructs the GraphState,
    and drives it through dispatch_agents → generate_plans → publish_plans.
    On success, marks the incident as 'plans_generated' in the DB.
    """
    pool = await _get_pool()
    async with pool.acquire() as conn:
        alert = await conn.fetchrow("SELECT * FROM incidents WHERE alert_id=$1", alert_id)
        if not alert:
            return {"status": "error", "error": "Alert not found"}

        # Reconstruct a feature_vector sub-dict so nodes that expect it work correctly.
        fv = {"src_ip": str(alert["src_ip"]), "dst_ip": str(alert["dst_ip"]), "dst_port": int(alert["dst_port"])}
        initial: GraphState = {
            "alert_id":  alert_id,
            "alert_raw": {
                "classification": alert["classification"],
                "anomaly_score":  float(alert["anomaly_score"]),
                "feature_vector": fv,
                **fv,
            },
            "classification": alert["classification"],
            "src_ip":        str(alert["src_ip"]),
            "dst_ip":        str(alert["dst_ip"]),
            "dst_port":      int(alert["dst_port"]),
            "anomaly_score": float(alert["anomaly_score"]),
            "asset_context": {}, "cve_matches": [], "plans": [],
            "status": "triaged", "error": "",
            "replan_context": replan_context,
        }

        result = await build_investigation_graph().ainvoke(initial)

        if result["status"] == "published":
            await conn.execute(
                "UPDATE incidents SET approval_status='plans_generated' WHERE alert_id=$1",
                alert_id,
            )
            logger.info("Alert %s -> plans_generated", alert_id)

        return result


# ---------------------------------------------------------------------------
# Private DB helpers
# ---------------------------------------------------------------------------

async def _ensure_incident_exists(alert_id: str, raw: dict, fv: dict):
    """Insert a new incident row if one does not already exist for alert_id.

    Uses INSERT … WHERE NOT EXISTS semantics via a SELECT check so we avoid
    primary-key conflicts when the same alert is replayed from Kafka.
    """
    try:
        pool = await _get_pool()
        async with pool.acquire() as conn:
            if not await conn.fetchval("SELECT 1 FROM incidents WHERE alert_id=$1", alert_id):
                ts_str = raw.get("timestamp")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
                except Exception:
                    ts = datetime.now(timezone.utc)
                await conn.execute(
                    """INSERT INTO incidents
                       (alert_id, timestamp, classification, anomaly_score,
                        src_ip, dst_ip, dst_port, approval_status, priority, created_at)
                       VALUES ($1,$2,$3,$4,$5::inet,$6::inet,$7,'received','medium',NOW())""",
                    alert_id, ts,
                    raw.get("classification", "unknown"),
                    float(raw.get("anomaly_score", 0)),
                    str(fv.get("src_ip", "0.0.0.0")),
                    str(fv.get("dst_ip", "0.0.0.0")),
                    int(fv.get("dst_port", 0)),
                )
                logger.info("Created incident %s", alert_id)
    except Exception as e:
        logger.warning("_ensure_incident_exists: %s", e)


async def _store_enrichment(alert_id: str, asset_ctx: dict, cve_matches: list):
    """Persist CVE matches and affected-asset metadata onto the incident row.

    Serialises both fields as JSONB so the dashboard can query them without
    joining additional tables.
    """
    try:
        pool = await _get_pool()
        async with pool.acquire() as conn:
            affected = []
            if asset_ctx.get("local_asset"):
                la = asset_ctx["local_asset"]
                affected.append({
                    "ip":               str(la.get("ip_address", "")),
                    "hostname":         la.get("hostname"),
                    "criticality_tier": la.get("criticality_tier"),
                    "zone":             la.get("zone"),
                })
            await conn.execute(
                "UPDATE incidents SET cve_matches=$2::jsonb, affected_assets=$3::jsonb WHERE alert_id=$1",
                alert_id,
                json.dumps(cve_matches, default=str),
                json.dumps(affected, default=str),
            )
    except Exception as e:
        logger.warning("_store_enrichment: %s", e)
