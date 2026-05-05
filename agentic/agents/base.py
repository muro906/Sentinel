"""
Base Agent Class
=================
Abstract base class for all sub-agents in the agentic layer. Provides:

1. Structured execution lifecycle (execute → validate → process → respond)
2. Automatic reasoning event emission at every step
3. Configurable retry logic with exponential backoff
4. Timeout enforcement
5. Error handling that captures failures as reasoning events

Every sub-agent (CVE Lookup, Asset Discovery, etc.) inherits from this class
and implements the `_process()` method with its specific logic.

The reasoning events emitted by the base class ensure the SOC analyst can
see exactly what each agent did, how long it took, and why it made its
decisions — even when an agent fails or times out.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from agentic.models.reasoning import ReasoningEvent, ReasoningEventType
from agentic.reasoning.emitter import emit_reasoning_event

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all sub-agents.

    Subclasses must implement:
        - name (property): unique agent identifier
        - _process(task_data): the actual agent logic

    The base class handles:
        - Timeout enforcement
        - Retry with exponential backoff
        - Reasoning event emission at start, completion, and failure
        - Duration tracking
    """

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        retry_base_delay: float = 1.0,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_base_delay = retry_base_delay

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique agent identifier (e.g., 'cve_lookup', 'asset_discovery')."""
        ...

    @abstractmethod
    async def _process(self, task_data: dict) -> dict:
        """
        Core agent logic. Implemented by subclasses.

        Args:
            task_data: Input data for this agent (from orchestrator dispatch)

        Returns:
            Result dict to be stored and sent back to orchestrator
        """
        ...

    async def execute(self, alert_id: str, task_data: dict) -> dict:
        """
        Public entry point. Wraps _process with timeout, retry, and reasoning events.

        This method:
        1. Emits AGENT_DISPATCHED reasoning event
        2. Calls _process() with timeout and retry
        3. Emits AGENT_RESULT or AGENT_ERROR/AGENT_TIMEOUT event
        4. Returns the result (or error dict)
        """
        start_time = time.time()

        # Emit dispatch event
        await emit_reasoning_event(ReasoningEvent(
            alert_id=alert_id,
            event_type=ReasoningEventType.AGENT_DISPATCHED,
            agent=self.name,
            action=f"Agent '{self.name}' dispatched",
            input_summary=self._summarize_input(task_data),
            rationale=f"Orchestrator dispatched {self.name} to gather context for alert {alert_id}",
        ))

        # Execute with retry
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                result = await asyncio.wait_for(
                    self._process(task_data),
                    timeout=self.timeout_seconds,
                )

                duration_ms = int((time.time() - start_time) * 1000)

                # Emit success event
                await emit_reasoning_event(ReasoningEvent(
                    alert_id=alert_id,
                    event_type=ReasoningEventType.AGENT_RESULT,
                    agent=self.name,
                    action=f"Agent '{self.name}' completed successfully",
                    input_summary=self._summarize_input(task_data),
                    output_summary=self._summarize_output(result),
                    full_input=task_data,
                    full_output=result,
                    rationale=self._explain_result(result),
                    duration_ms=duration_ms,
                    confidence=result.get("_confidence"),
                ))

                return result

            except asyncio.TimeoutError:
                duration_ms = int((time.time() - start_time) * 1000)
                last_error = f"Timeout after {self.timeout_seconds}s (attempt {attempt + 1})"
                logger.warning(f"{self.name}: {last_error}")

                if attempt < self.max_retries:
                    delay = self.retry_base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
                    continue

                # Final timeout — emit event
                await emit_reasoning_event(ReasoningEvent(
                    alert_id=alert_id,
                    event_type=ReasoningEventType.AGENT_TIMEOUT,
                    agent=self.name,
                    action=f"Agent '{self.name}' timed out after {self.max_retries + 1} attempts",
                    input_summary=self._summarize_input(task_data),
                    rationale=f"Agent exceeded {self.timeout_seconds}s timeout on all {self.max_retries + 1} attempts. "
                              f"Orchestrator will proceed with partial results.",
                    duration_ms=duration_ms,
                    error=last_error,
                ))

                return {"_error": last_error, "_agent": self.name, "_timeout": True}

            except Exception as e:
                duration_ms = int((time.time() - start_time) * 1000)
                last_error = f"{type(e).__name__}: {str(e)}"
                logger.error(f"{self.name} error (attempt {attempt + 1}): {last_error}")

                if attempt < self.max_retries:
                    delay = self.retry_base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
                    continue

                # Final error — emit event
                await emit_reasoning_event(ReasoningEvent(
                    alert_id=alert_id,
                    event_type=ReasoningEventType.AGENT_ERROR,
                    agent=self.name,
                    action=f"Agent '{self.name}' failed after {self.max_retries + 1} attempts",
                    input_summary=self._summarize_input(task_data),
                    rationale=f"Agent encountered error: {last_error}. "
                              f"Orchestrator will proceed with partial results.",
                    duration_ms=duration_ms,
                    error=last_error,
                ))

                return {"_error": last_error, "_agent": self.name, "_timeout": False}

    def _summarize_input(self, task_data: dict) -> str:
        """Create a concise input summary for the reasoning trace timeline."""
        parts = []
        if "src_ip" in task_data:
            parts.append(f"src={task_data['src_ip']}")
        if "dst_ip" in task_data:
            parts.append(f"dst={task_data['dst_ip']}")
        if "dst_port" in task_data:
            parts.append(f"port={task_data['dst_port']}")
        if "classification" in task_data:
            parts.append(f"type={task_data['classification']}")
        return ", ".join(parts) if parts else str(list(task_data.keys()))

    def _summarize_output(self, result: dict) -> str:
        """Create a concise output summary. Override in subclasses for better summaries."""
        return f"Result keys: {list(result.keys())}"

    def _explain_result(self, result: dict) -> str:
        """Generate a rationale for the result. Override in subclasses."""
        return f"Agent '{self.name}' completed processing and returned results."
