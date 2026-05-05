"""
Sentinel Orchestrator — Main Entry Point
==========================================
Starts the agentic layer:

1. Connects to Kafka, Redis, and PostgreSQL
2. Compiles the LangGraph orchestrator graph
3. Starts the reasoning trace persister (background task)
4. Enters the main loop: poll Kafka for alerts, invoke the graph
5. Handles graceful shutdown on SIGINT/SIGTERM

The orchestrator is the central brain of Layer 3. It receives anomaly alerts,
dispatches sub-agents, invokes the LLM for plan generation, and publishes
plans to the SOC dashboard for human approval.
"""

import asyncio
import json
import logging
import os
import signal
import sys

from agentic.kafka.consumer import AlertConsumer
from agentic.orchestrator.graph import build_orchestrator_graph
from agentic.execution.approval_handler import ApprovalHandler
from agentic.reasoning.trace import persist_traces_loop
from agentic.state.redis_client import close_redis
from agentic.db.connection import close_pool

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sentinel.orchestrator")


class Orchestrator:
    """Main orchestrator process coordinating all agentic layer components."""

    def __init__(self):
        self._running = False
        self._consumer = AlertConsumer()
        self._graph = None
        self._trace_task = None
        self._approval_handler = ApprovalHandler(
            dry_run=os.environ.get("DRY_RUN", "true").lower() == "true"
        )
        self._approval_task = None

    async def start(self):
        """Initialize connections and compile the graph."""
        logger.info("=" * 60)
        logger.info("  Sentinel Orchestrator starting...")
        logger.info("=" * 60)

        # 1. Build the LangGraph state machine
        self._graph = build_orchestrator_graph()
        logger.info("LangGraph orchestrator compiled")

        # 2. Connect to Kafka
        self._consumer.connect()

        # 3. Start background trace persister (Redis → PostgreSQL)
        self._trace_task = asyncio.create_task(persist_traces_loop())
        logger.info("Reasoning trace persister started")

        # 4. Start approval handler (consumes approved-actions, triggers execution)
        self._approval_handler.start()
        self._approval_task = asyncio.create_task(self._approval_handler.run())
        logger.info("Approval handler started")

        self._running = True
        logger.info("Orchestrator ready — listening for anomaly alerts")

    async def run(self):
        """Main processing loop: poll Kafka → invoke graph."""
        while self._running:
            try:
                # Poll Kafka for a message (1 second timeout)
                result = self._consumer.poll(timeout=1.0)

                if result is None:
                    await asyncio.sleep(0.1)  # yield to event loop
                    continue

                topic, data = result

                if topic == "anomaly-alerts":
                    await self._process_alert(data)
                elif topic == "action-results":
                    await self._process_action_result(data)

                # Commit offset after successful processing
                self._consumer.commit()

            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                await asyncio.sleep(1)  # back off on error

    async def _process_alert(self, alert_data: dict):
        """Process a single anomaly alert through the LangGraph pipeline."""
        alert_id = alert_data.get("alert_id", "unknown")
        logger.info(f"Processing alert: {alert_id}")

        try:
            # Invoke the graph with the alert as initial state
            result = await self._graph.ainvoke({
                "alert_raw": alert_data,
            })

            # Log outcome
            plans = result.get("plans", [])
            priority = result.get("priority", "unknown")
            is_dup = result.get("is_duplicate", False)

            if is_dup:
                logger.info(f"Alert {alert_id}: duplicate, skipped")
            elif plans:
                best = plans[0].get("confidence", 0)
                logger.info(
                    f"Alert {alert_id}: {priority} priority, "
                    f"{len(plans)} plans generated (best confidence: {best:.2f})"
                )
            else:
                logger.warning(f"Alert {alert_id}: no plans generated")

        except Exception as e:
            logger.error(f"Failed to process alert {alert_id}: {e}", exc_info=True)

    async def _process_action_result(self, result_data: dict):
        """
        Process an action result from the execution layer.
        If an action failed, may trigger re-planning.
        """
        alert_id = result_data.get("alert_id", "unknown")
        action_id = result_data.get("action_id", "unknown")
        status = result_data.get("status", "unknown")

        logger.info(f"Action result: {action_id} for alert {alert_id} → {status}")

        if status == "failed":
            logger.warning(
                f"Action {action_id} failed: {result_data.get('error', 'no details')}. "
                f"Consider re-planning for alert {alert_id}"
            )
            # Future: trigger handle_failure node via the graph

    async def shutdown(self):
        """Graceful shutdown: close all connections."""
        logger.info("Orchestrator shutting down...")
        self._running = False

        # Cancel trace persister
        if self._trace_task:
            self._trace_task.cancel()
            try:
                await self._trace_task
            except asyncio.CancelledError:
                pass

        # Stop approval handler
        if self._approval_task:
            self._approval_handler.stop()
            self._approval_task.cancel()
            try:
                await self._approval_task
            except asyncio.CancelledError:
                pass

        # Close connections
        self._consumer.close()
        await close_redis()
        await close_pool()

        logger.info("Orchestrator shutdown complete")


async def main():
    """Entry point: start orchestrator with signal handling."""
    orchestrator = Orchestrator()

    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(orchestrator.shutdown()))

    await orchestrator.start()

    try:
        await orchestrator.run()
    except asyncio.CancelledError:
        pass
    finally:
        await orchestrator.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
