"""
LangGraph Orchestrator Graph
==============================
Defines the state machine that orchestrates the full alert processing pipeline.

Graph topology:
    ┌──────────────┐
    │ receive_alert │
    └──────┬───────┘
           │
    ┌──────▼───────┐
    │    triage     │──── duplicate? ──→ END
    └──────┬───────┘
           │
    ┌──────▼────────────┐
    │  dispatch_agents   │   (CVE + Asset in parallel)
    └──────┬────────────┘
           │
    ┌──────▼───────┐
    │   aggregate   │
    └──────┬───────┘
           │
    ┌──────▼────────────┐
    │  generate_plans    │ ◄── re-plan loop
    └──────┬────────────┘
           │
    ┌──────▼────────────┐
    │  publish_plans     │──── execution failed? ──→ handle_failure ──┐
    └──────┬────────────┘                                              │
           │                                                           │
          END  (dashboard takes over for approval → execution)         │
                                                                       │
    ┌──────────────────┐◄──────────────────────────────────────────────┘
    │  handle_failure   │──── should_replan? ──→ generate_plans (loop)
    └──────────────────┘                  └────→ END

The approval and execution nodes are triggered externally (via Kafka messages
from the dashboard/execution layer), not within this graph run. This keeps
the orchestrator non-blocking — it publishes plans and moves on to the next
alert.
"""

import logging

from langgraph.graph import StateGraph, END

from agentic.orchestrator.state import OrchestratorState
from agentic.orchestrator.nodes import (
    receive_alert,
    triage,
    dispatch_agents,
    aggregate,
    generate_plans,
    publish_plans,
    handle_failure,
    should_continue_after_triage,
    should_replan_or_end,
    should_handle_failure,
)

logger = logging.getLogger(__name__)


def build_orchestrator_graph() -> StateGraph:
    """
    Construct the LangGraph state machine for alert processing.

    Returns a compiled graph that can be invoked with:
        result = await graph.ainvoke({"alert_raw": alert_dict})
    """
    # Create the graph with our state schema
    graph = StateGraph(OrchestratorState)

    # ── Add Nodes ──────────────────────────────────────────────────────────────
    graph.add_node("receive_alert", receive_alert)
    graph.add_node("triage", triage)
    graph.add_node("dispatch_agents", dispatch_agents)
    graph.add_node("aggregate", aggregate)
    graph.add_node("generate_plans", generate_plans)
    graph.add_node("publish_plans", publish_plans)
    graph.add_node("handle_failure", handle_failure)

    # ── Set Entry Point ────────────────────────────────────────────────────────
    graph.set_entry_point("receive_alert")

    # ── Add Edges ──────────────────────────────────────────────────────────────
    # Linear flow: receive → triage
    graph.add_edge("receive_alert", "triage")

    # Conditional: triage → dispatch_agents OR end (if duplicate/low score)
    graph.add_conditional_edges(
        "triage",
        should_continue_after_triage,
        {
            "dispatch_agents": "dispatch_agents",
            "end": END,
        }
    )

    # Linear flow: dispatch → aggregate → plans → publish
    graph.add_edge("dispatch_agents", "aggregate")
    graph.add_edge("aggregate", "generate_plans")
    graph.add_edge("generate_plans", "publish_plans")

    # Publish → end normally, or → handle_failure if execution came back failed
    graph.add_conditional_edges(
        "publish_plans",
        should_handle_failure,
        {
            "handle_failure": "handle_failure",
            "end": END,
        }
    )

    # Handle failure → conditional re-plan or end
    graph.add_conditional_edges(
        "handle_failure",
        should_replan_or_end,
        {
            "generate_plans": "generate_plans",
            "end": END,
        }
    )

    # ── Compile ────────────────────────────────────────────────────────────────
    compiled = graph.compile()
    logger.info("Orchestrator graph compiled successfully")

    return compiled
