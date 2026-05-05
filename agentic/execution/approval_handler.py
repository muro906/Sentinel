"""
Approval Handler
=================
Consumes approved-action messages from Kafka and triggers execution.
This bridges the gap between the orchestrator (which publishes plans)
and the execution layer (which runs actions).

Flow:
1. SOC analyst reviews plans on the dashboard
2. Analyst approves a plan → dashboard publishes to 'approved-actions' topic
3. This handler consumes the message
4. Routes each action to the appropriate executor via the router
5. Publishes results to 'action-results' topic for the orchestrator feedback loop

The handler also supports auto-execution for high-confidence plans
where the automation tier is 'auto_execute'.
"""

import asyncio
import json
import logging
import os
import time

from agentic.execution.router import execute_plan, init_executors
from agentic.kafka.consumer import AlertConsumer
from agentic.kafka.producer import PlanProducer
from agentic.models.plan import ActionResult
from agentic.models.reasoning import ReasoningEvent, ReasoningEventType
from agentic.reasoning.emitter import emit_reasoning_event
from agentic.state.session import update_session

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


class ApprovalHandler:
    """
    Listens for approved-action Kafka messages and triggers execution.
    Runs as a separate asyncio task alongside the orchestrator.
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._running = False
        self._consumer = None
        self._producer = None

    def start(self):
        """Initialize executors and Kafka connections."""
        init_executors(dry_run=self.dry_run)

        # Consumer for approved-actions topic
        from confluent_kafka import Consumer, KafkaError

        self._consumer = Consumer({
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": "sentinel-executor",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
        })
        self._consumer.subscribe(["approved-actions"])

        # Producer for action-results topic
        from confluent_kafka import Producer
        self._producer = Producer({
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "acks": "all",
        })

        self._running = True
        logger.info(f"Approval handler started (dry_run={self.dry_run})")

    async def run(self):
        """Main loop: poll for approved actions and execute them."""
        while self._running:
            try:
                msg = self._consumer.poll(timeout=1.0)
                if msg is None:
                    await asyncio.sleep(0.1)
                    continue
                if msg.error():
                    logger.error(f"Kafka consumer error: {msg.error()}")
                    continue

                # Parse the approved-action message
                try:
                    data = json.loads(msg.value().decode("utf-8"))
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON in approved-actions: {msg.value()}")
                    self._consumer.commit(asynchronous=False)
                    continue

                await self._handle_approval(data)
                self._consumer.commit(asynchronous=False)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Approval handler error: {e}", exc_info=True)
                await asyncio.sleep(1)

    async def _handle_approval(self, data: dict):
        """Process an approved plan: extract actions and execute."""
        alert_id = data.get("alert_id", "unknown")
        plan_id = data.get("plan_id", "unknown")
        actions = data.get("actions", [])
        approved_by = data.get("approved_by", "unknown")
        approval_notes = data.get("notes", "")

        logger.info(
            f"Received approval: plan={plan_id}, alert={alert_id}, "
            f"actions={len(actions)}, by={approved_by}"
        )

        await emit_reasoning_event(ReasoningEvent(
            alert_id=alert_id,
            event_type=ReasoningEventType.PLAN_APPROVED,
            agent="executor",
            action=f"Plan {plan_id} approved by {approved_by}",
            input_summary=f"{len(actions)} actions to execute",
            rationale=f"Analyst '{approved_by}' approved plan {plan_id}. "
                      f"{'Notes: ' + approval_notes if approval_notes else 'No additional notes.'}",
        ))

        await update_session(alert_id, {
            "state": "executing",
            "approved_at": str(time.time()),
            "approved_by": approved_by,
        })

        # Execute the plan
        results = await execute_plan(
            alert_id=alert_id,
            plan_id=plan_id,
            actions=actions,
            stop_on_failure=data.get("stop_on_failure", True),
        )

        # Publish results to action-results topic
        for result in results:
            result_dict = result.model_dump(mode="json")
            self._producer.produce(
                "action-results",
                key=alert_id.encode("utf-8"),
                value=json.dumps(result_dict).encode("utf-8"),
            )
        self._producer.flush()

        # Update session
        failed = [r for r in results if r.status == "failed"]
        await update_session(alert_id, {
            "state": "executed" if not failed else "execution_failed",
            "executed_at": str(time.time()),
        })

        logger.info(
            f"Plan {plan_id} execution complete: "
            f"{sum(1 for r in results if r.status == 'completed')} succeeded, "
            f"{len(failed)} failed, "
            f"{sum(1 for r in results if r.status == 'skipped')} skipped"
        )

    async def handle_auto_execute(self, alert_id: str, plan: dict):
        """
        Auto-execute a plan without human approval.
        Called by the orchestrator when automation_tier == 'auto_execute'.
        """
        plan_id = plan.get("plan_id", "auto")
        actions = plan.get("actions", [])

        await emit_reasoning_event(ReasoningEvent(
            alert_id=alert_id,
            event_type=ReasoningEventType.PLAN_APPROVED,
            agent="executor",
            action=f"Plan {plan_id} AUTO-APPROVED (confidence >= 95%)",
            input_summary=f"{len(actions)} actions",
            rationale="Plan confidence meets auto-execute threshold (≥95%). "
                      "Executing without human approval per policy.",
        ))

        results = await execute_plan(
            alert_id=alert_id,
            plan_id=plan_id,
            actions=actions,
            stop_on_failure=True,
        )

        return results

    def stop(self):
        """Shutdown the handler."""
        self._running = False
        if self._consumer:
            self._consumer.close()
        if self._producer:
            self._producer.flush()
        logger.info("Approval handler stopped")
