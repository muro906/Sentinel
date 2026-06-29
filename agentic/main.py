"""
Main entry point for the simplified agentic orchestrator.
Consumes alerts from Kafka, processes through LangGraph, publishes plans.
Also consumes approved-actions and executes plans.
"""
import asyncio
import logging
import os
import signal
import sys

from kafka.consumer import AlertConsumer
from graph import process_alert, process_investigation
from execution import ExecutionHandler
from confluent_kafka import Consumer, KafkaError
import json

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger("sentinel.orchestrator")


class Orchestrator:
    """Main orchestrator process."""
    
    def __init__(self):
        self._running = False
        self._consumer = AlertConsumer()
        self._execution_handler = ExecutionHandler()
        self._investigation_consumer = None
    
    async def start(self):
        """Initialize and start the orchestrator."""
        logger.info("=" * 60)
        logger.info("  Sentinel Orchestrator starting...")
        logger.info("=" * 60)
        
        # Connect to Kafka
        self._consumer.connect()
        self._execution_handler.connect()
        self._connect_investigation_consumer()
        
        self._running = True
        logger.info("Orchestrator ready — listening for anomaly alerts, investigation requests, and approved actions")
    
    def _connect_investigation_consumer(self):
        """Pre-create topics then connect investigation and re-plan consumers.

        Topics are created eagerly so consumers never get UNKNOWN_TOPIC_OR_PART
        on their first poll.  Both consumers use 'earliest' so that a message
        published just before a restart is never silently dropped.
        """
        from confluent_kafka.admin import AdminClient, NewTopic
        from confluent_kafka import KafkaException

        bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

        # Ensure all topics exist before subscribing
        admin = AdminClient({"bootstrap.servers": bootstrap_servers})
        topics_to_create = [
            NewTopic("investigation-requests", num_partitions=1, replication_factor=1),
            NewTopic("replan-requests",        num_partitions=1, replication_factor=1),
        ]
        futures = admin.create_topics(topics_to_create, request_timeout=10.0)
        for topic, fut in futures.items():
            try:
                fut.result()
                logger.info("Created topic: %s", topic)
            except Exception as exc:
                # TOPIC_ALREADY_EXISTS is expected and fine; log anything else
                msg = str(exc)
                if "already exists" not in msg.lower():
                    logger.warning("Topic creation warning for %s: %s", topic, exc)

        self._investigation_consumer = Consumer({
            "bootstrap.servers":    bootstrap_servers,
            "group.id":             "sentinel-investigation",
            "auto.offset.reset":    "earliest",   # never miss a message on restart
            "enable.auto.commit":   False,
            # LLM calls can take >5 min; raise the poll deadline so Kafka
            # doesn't force-leave the group mid-investigation.
            "max.poll.interval.ms": "600000",     # 10 minutes
        })
        self._investigation_consumer.subscribe(["investigation-requests"])

        self._replan_consumer = Consumer({
            "bootstrap.servers":    bootstrap_servers,
            "group.id":             "sentinel-replan",
            "auto.offset.reset":    "earliest",
            "enable.auto.commit":   False,
            "max.poll.interval.ms": "600000",
        })
        self._replan_consumer.subscribe(["replan-requests"])
        logger.info("Investigation + re-plan consumers connected")

    async def run(self):
        """Main processing loop - runs all consumers in parallel."""
        alert_task         = asyncio.create_task(self._run_alert_consumer())
        investigation_task = asyncio.create_task(self._run_investigation_consumer())
        execution_task     = asyncio.create_task(self._execution_handler.run())
        replan_task        = asyncio.create_task(self._run_replan_consumer())
        
        try:
            await asyncio.gather(alert_task, investigation_task, execution_task, replan_task)
        except asyncio.CancelledError:
            pass
    
    async def _run_alert_consumer(self):
        """Run the alert consumer loop."""
        while self._running:
            try:
                # Poll Kafka for a message
                result = self._consumer.poll(timeout=1.0)
                
                if result is None:
                    await asyncio.sleep(0.1)
                    continue
                
                topic, data = result
                
                if topic == "anomaly-alerts":
                    await self._process_alert(data)
                
                # Commit offset after successful processing
                self._consumer.commit()
                
            except Exception as e:
                logger.error(f"Error in alert consumer loop: {e}", exc_info=True)
                await asyncio.sleep(1)
    
    async def _process_alert(self, alert_data: dict):
        """Process a single anomaly alert through the graph."""
        alert_id = alert_data.get("alert_id", "unknown")
        logger.info(f"Processing alert: {alert_id}")
        
        try:
            # Process through LangGraph (ingestion only)
            result = await process_alert(alert_data)
            
            # Log outcome
            status = result.get("status", "unknown")
            
            logger.info(f"Alert {alert_id}: status={status}")
            
        except Exception as e:
            logger.error(f"Failed to process alert {alert_id}: {e}", exc_info=True)
    
    async def _run_investigation_consumer(self):
        """Run the investigation request consumer loop."""
        while self._running:
            try:
                # Poll Kafka for a message
                msg = self._investigation_consumer.poll(timeout=1.0)
                
                if msg is None:
                    await asyncio.sleep(0.1)
                    continue
                
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error(f"Kafka error: {msg.error()}")
                    continue
                
                try:
                    data = json.loads(msg.value().decode("utf-8"))
                    await self._process_investigation(data)
                    self._investigation_consumer.commit(msg)
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    logger.warning(f"Failed to decode investigation message: {e}")
                    self._investigation_consumer.commit(msg)
                except Exception as e:
                    logger.error(f"Failed to process investigation: {e}", exc_info=True)
                    
            except Exception as e:
                logger.error(f"Error in investigation consumer loop: {e}", exc_info=True)
                await asyncio.sleep(1)
    
    async def _process_investigation(self, investigation_data: dict):
        alert_id      = investigation_data.get("alert_id", "unknown")
        requested_by  = investigation_data.get("requested_by", "unknown")
        replan_context = investigation_data.get("replan_context", "")
        if replan_context:
            logger.info(f"Replan requested for {alert_id} by {requested_by}: {replan_context[:80]}")
        else:
            logger.info(f"Processing investigation for {alert_id} by {requested_by}")
        try:
            result = await process_investigation(alert_id, replan_context=replan_context)
            logger.info(f"Investigation {alert_id}: status={result.get('status')} plans={len(result.get('plans',[]))}")
        except Exception as e:
            logger.error(f"Investigation {alert_id} failed: {e}", exc_info=True)

    async def _run_replan_consumer(self):
        """Consume replan-requests and re-run investigation with failure context."""
        while self._running:
            try:
                msg = self._replan_consumer.poll(timeout=1.0)
                if msg is None:
                    await asyncio.sleep(0.1)
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error(f"Replan Kafka error: {msg.error()}")
                    continue
                try:
                    data = json.loads(msg.value().decode("utf-8"))
                    alert_id = data.get("alert_id", "unknown")
                    summary  = data.get("failure_summary", "previous plan failed")
                    attempt  = data.get("replan_attempt", 1)
                    logger.info(f"Re-plan requested for {alert_id} (attempt {attempt}): {summary}")
                    context = f"PREVIOUS PLAN FAILED (attempt {attempt}): {summary}. Generate a more effective plan."
                    result  = await process_investigation(alert_id, replan_context=context)
                    logger.info(f"Re-plan {alert_id}: status={result.get('status')}")
                    self._replan_consumer.commit(msg)
                except Exception as e:
                    logger.error(f"Re-plan processing failed: {e}", exc_info=True)
            except Exception as e:
                logger.error(f"Replan consumer loop error: {e}", exc_info=True)
                await asyncio.sleep(1)

    async def shutdown(self):
        """Graceful shutdown."""
        logger.info("Orchestrator shutting down...")
        self._running = False
        self._consumer.close()
        self._execution_handler.close()
        if hasattr(self, '_replan_consumer') and self._replan_consumer:
            self._replan_consumer.close()
        if self._investigation_consumer:
            self._investigation_consumer.close()
        logger.info("Orchestrator shutdown complete")


async def main():
    """Entry point."""
    orchestrator = Orchestrator()
    
    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig,
            lambda: asyncio.create_task(orchestrator.shutdown())
        )
    
    await orchestrator.start()
    
    try:
        await orchestrator.run()
    except asyncio.CancelledError:
        pass
    finally:
        await orchestrator.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
