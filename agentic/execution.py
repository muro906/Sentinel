"""Execution handler — consumes approved-actions, runs real commands, verifies, re-plans on failure."""
import asyncio
import json
import logging
import os
import shlex
from datetime import datetime, timezone
from typing import Optional

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from confluent_kafka.admin import AdminClient, NewTopic

from llm_client import GroqClient
from reasoning import emit_trace

logger = logging.getLogger(__name__)

MAX_REPLAN_ATTEMPTS = 1  # allow one automatic re-plan before giving up

# ── Simulation / dry-run configuration ────────────────────────────────────────
# DRY_RUN=true         → simulate ALL action types
# DRY_RUN_ACTIONS=a,b  → simulate only the listed action types (comma-separated)
# Default: destructive/irreversible actions are simulated; safe ones (notify,
# deep_inspect) execute for real.
_DRY_RUN_GLOBAL = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")
_DRY_RUN_TYPES: set[str] = {
    t.strip()
    for t in os.getenv(
        "DRY_RUN_ACTIONS",
        "firewall_block,isolate_host,firewall_unblock,restore_host,credential_rotate,rate_limit,patch"
    ).split(",")
    if t.strip()
}


def _is_dry_run(action_type: str) -> bool:
    return _DRY_RUN_GLOBAL or action_type in _DRY_RUN_TYPES


# ── Docker-exec asset map ─────────────────────────────────────────────────────
# When ASSET_EXEC_MODE=docker_exec the executor runs commands inside the target
# asset container rather than on the orchestrator host.
# Overridable via env: ASSET_CONTAINER_MAP="10.0.0.1=container-name;..."
_DEFAULT_ASSET_MAP: dict[str, str] = {
    "10.0.0.1":      "sentinel-asset-web-prod-01",
    "10.0.0.2":      "sentinel-asset-web-prod-02",
    "10.0.0.10":     "sentinel-asset-api-gateway",
    "10.0.0.53":     "sentinel-asset-dns-resolver",
    "192.168.1.100": "sentinel-asset-db-internal",
    "192.168.1.200": "sentinel-asset-auth-server",
}
_ASSET_MAP: dict[str, str] = {
    ip.strip(): name.strip()
    for pair in os.getenv("ASSET_CONTAINER_MAP", "").split(";")
    if "=" in pair
    for ip, name in [pair.split("=", 1)]
} or _DEFAULT_ASSET_MAP


class ExecutionHandler:

    def __init__(self):
        self._bs = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        self._consumer: Optional[Consumer] = None
        self._producer: Optional[Producer] = None
        self._running = False
        self._llm = GroqClient()

    # ── Kafka setup ────────────────────────────────────────────────────────────

    def _ensure_topics(self):
        admin = AdminClient({"bootstrap.servers": self._bs})
        for topic in ("approved-actions", "action-results", "replan-requests"):
            f = admin.create_topics(
                [NewTopic(topic, num_partitions=1, replication_factor=1)],
                request_timeout=10.0
            )
            for _, fut in f.items():
                try:
                    fut.result()
                except KafkaException as e:
                    if e.args[0].code() != KafkaError.TOPIC_ALREADY_EXISTS:
                        logger.warning("Topic create: %s", e)

    def connect(self):
        self._ensure_topics()
        self._consumer = Consumer({
            "bootstrap.servers": self._bs,
            "group.id": "sentinel-execution",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
            # Execution (LLM + shell commands + verification) can take many minutes;
            # raise the poll interval so Kafka doesn't kick us mid-run and replay the message.
            "max.poll.interval.ms": 1_800_000,  # 30 minutes
            "session.timeout.ms":   30_000,
        })
        self._consumer.subscribe(["approved-actions"])
        self._producer = Producer({"bootstrap.servers": self._bs, "acks": "all"})
        self._running = True
        logger.info("Execution handler connected to %s", self._bs)

    def close(self):
        self._running = False
        if self._consumer:
            self._consumer.close()
        if self._producer:
            self._producer.flush(10.0)
        logger.info("Execution handler closed")

    # ── Main loop ──────────────────────────────────────────────────────────────

    async def run(self):
        while self._running:
            try:
                msg = self._consumer.poll(1.0)
                if msg is None:
                    await asyncio.sleep(0.1)
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error("Kafka error: %s", msg.error())
                    continue
                try:
                    data = json.loads(msg.value().decode())
                    await self.process_approval(data)
                    self._consumer.commit(msg)
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    logger.warning("Bad message: %s", e)
                    self._consumer.commit(msg)
                except Exception as e:
                    logger.error("process_approval failed: %s", e, exc_info=True)
            except Exception as e:
                logger.error("Execution loop error: %s", e, exc_info=True)
                await asyncio.sleep(1)

    # ── Approval processing ────────────────────────────────────────────────────

    async def process_approval(self, approval: dict):
        alert_id    = approval.get("alert_id", "unknown")
        plan_id     = approval.get("plan_id", "unknown")
        actions     = approval.get("actions", [])
        approved_by = approval.get("approved_by", "unknown")
        attempt     = approval.get("replan_attempt", 0)

        # Idempotency guard: skip if the alert already reached a terminal state.
        # This prevents double-execution when Kafka replays a message after a
        # consumer timeout (max.poll.interval.ms exceeded).
        current_status = await self._fetch_alert_status(alert_id)
        if current_status in ("closed", "rejected", "executed"):
            logger.warning(
                "Skipping execution for %s: already in terminal state '%s'",
                alert_id, current_status
            )
            return

        logger.info("Executing plan %s for alert %s (attempt %d)", plan_id, alert_id, attempt)
        await emit_trace(
            alert_id=alert_id, event_type="execution_started", agent="executor",
            action=f"Executing {len(actions)} approved actions (plan {plan_id})",
            rationale=f"Plan approved by {approved_by}. Beginning automated execution."
        )

        # Fetch alert context for command generation
        alert_context = await self._fetch_alert_context(alert_id)

        results = []
        all_ok = True

        for action in actions:
            action_type = action.get("action_type", "unknown")
            target      = action.get("target", "")
            params      = action.get("parameters", {})

            await emit_trace(
                alert_id=alert_id, event_type="action_started", agent="executor",
                action=f"Starting {action_type} on {target}",
                rationale=f"Executing: {action_type} → {target}"
            )

            result = await self._execute_action(alert_id, action_type, target, params, alert_context)
            results.append(result)

            if result["status"] == "success":
                await emit_trace(
                    alert_id=alert_id, event_type="action_completed", agent="executor",
                    action=f"Completed {action_type} on {target}",
                    output_summary=result.get("output", "")[:200],
                    rationale=result.get("description", "Action completed successfully.")
                )
            else:
                all_ok = False
                await emit_trace(
                    alert_id=alert_id, event_type="action_failed", agent="executor",
                    action=f"Failed {action_type} on {target}",
                    rationale=f"Action failed: {result.get('error', 'unknown error')}",
                    error=result.get("error")
                )

        # ── Verification ───────────────────────────────────────────────────────
        if all_ok:
            verified = await self._verify_mitigation(alert_id, actions, alert_context)
        else:
            verified = False

        if verified or attempt >= MAX_REPLAN_ATTEMPTS:
            final_status = "closed" if verified else "execution_failed"
            await self._update_incident_status(alert_id, final_status, results)
            await self._publish_results(alert_id, results, verified)
            await emit_trace(
                alert_id=alert_id, event_type="execution_completed", agent="executor",
                action=f"Execution {'succeeded' if verified else 'completed with failures'}: "
                       f"{sum(1 for r in results if r['status']=='success')}/{len(results)} actions ok",
                rationale="Threat mitigated." if verified else
                          "Execution done but threat may persist. Manual review required."
            )
            logger.info("Alert %s → %s", alert_id, final_status)
        else:
            # Re-plan: threat still present after executing the plan
            await emit_trace(
                alert_id=alert_id, event_type="verification_failed", agent="executor",
                action="Threat mitigation verification failed — triggering re-plan",
                rationale="Actions executed but threat indicators still present. "
                          "Generating new plan with failure context."
            )
            await self._trigger_replan(alert_id, plan_id, results, approved_by, attempt + 1)

    # ── Single action execution ────────────────────────────────────────────────

    async def _execute_action(
        self, alert_id: str, action_type: str, target: str,
        params: dict, alert_context: dict
    ) -> dict:
        # Ask LLM to generate specific commands
        try:
            cmd_spec = await self._llm.generate_execution_commands(
                action_type, target, params, alert_context
            )
        except Exception as e:
            logger.error("Command generation failed: %s", e)
            cmd_spec = self._llm._fallback_commands(action_type, target, params)

        commands        = cmd_spec.get("commands", [])
        verify_command  = cmd_spec.get("verify_command", "echo ok")
        description     = cmd_spec.get("description", f"{action_type} on {target}")

        await emit_trace(
            alert_id=alert_id, event_type="commands_generated", agent="executor",
            action=f"LLM generated {len(commands)} command(s) for {action_type}",
            output_summary="; ".join(commands[:2]),
            full_output=cmd_spec,
            rationale=description
        )

        # ── Simulation path ────────────────────────────────────────────────────
        if _is_dry_run(action_type):
            await emit_trace(
                alert_id=alert_id, event_type="commands_simulated", agent="executor",
                action=f"[SIMULATED] {action_type} on {target} — {len(commands)} command(s) generated",
                output_summary="; ".join(commands[:3]),
                full_output={
                    "mode": "dry_run",
                    "commands": commands,
                    "verify_command": verify_command,
                    "description": description,
                },
                rationale=(
                    f"DRY_RUN active for action type '{action_type}'. "
                    "Commands shown are what would execute on the target host. "
                    "No system changes were made."
                ),
            )
            logger.info("[dry-run] %s on %s — skipped execution", action_type, target)
            return {
                "action_type": action_type,
                "target":      target,
                "status":      "success",
                "description": f"[SIMULATED] {description}",
                "commands":    commands,
                "output":      f"[DRY RUN] Would have executed: {'; '.join(commands)}",
                "verify_rc":   0,
                "error":       None,
                "simulated":   True,
            }

        # ── Live execution path ────────────────────────────────────────────────
        # Determine runner: docker exec into asset container or local shell.
        container = _ASSET_MAP.get(target)
        use_docker_exec = (
            container is not None
            and os.getenv("ASSET_EXEC_MODE", "local") == "docker_exec"
        )

        async def _run(cmd: str) -> tuple[str, int]:
            if use_docker_exec:
                return await self._run_on_asset(container, cmd)
            return await self._run_shell(cmd)

        all_outputs = []
        for cmd in commands:
            out, rc = await _run(cmd)
            all_outputs.append({"cmd": cmd, "output": out, "returncode": rc})
            logger.info("[exec%s] %s → rc=%d",
                        f":docker({container})" if use_docker_exec else "",
                        cmd[:80], rc)

        # Run verify command (locally — checks orchestrator iptables / ss state)
        verify_out, verify_rc = await self._run_shell(verify_command)

        success = verify_rc == 0
        combined_output = "\n".join(o["output"][:300] for o in all_outputs)

        return {
            "action_type":  action_type,
            "target":       target,
            "status":       "success" if success else "failed",
            "description":  description,
            "commands":     commands,
            "output":       combined_output,
            "verify_rc":    verify_rc,
            "error":        None if success else f"Verify command exited {verify_rc}: {verify_out[:200]}",
            "simulated":    False,
        }

    async def _run_on_asset(self, container: str, cmd: str, timeout: int = 20) -> tuple[str, int]:
        """Run a command inside a target asset container via docker exec."""
        return await self._run_shell(
            f"docker exec {container} sh -c {shlex.quote(cmd)}", timeout
        )

    async def _run_shell(self, cmd: str, timeout: int = 20) -> tuple[str, int]:
        """Run a shell command, return (stdout+stderr, returncode)."""
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode(errors="replace").strip(), proc.returncode or 0
        except asyncio.TimeoutError:
            return f"Command timed out after {timeout}s", 1
        except Exception as e:
            return str(e), 1

    # ── Verification ──────────────────────────────────────────────────────────

    async def _verify_mitigation(
        self, alert_id: str, actions: list, alert_context: dict
    ) -> bool:
        """Check whether threat indicators are still present after execution."""
        if _DRY_RUN_GLOBAL or all(_is_dry_run(a.get("action_type", "")) for a in actions):
            await emit_trace(
                alert_id=alert_id, event_type="verification_simulated", agent="executor",
                action="Verification skipped — all actions were simulated",
                rationale="DRY_RUN active: no real changes were made, verification is a no-op."
            )
            return True

        src_ip = alert_context.get("src_ip", "")
        if not src_ip or src_ip == "unknown":
            # No src IP to verify against — assume success
            return True

        await emit_trace(
            alert_id=alert_id, event_type="verification_started", agent="executor",
            action=f"Verifying mitigation for source {src_ip}",
            rationale="Checking whether threat is still active after executing plan."
        )

        # Check 1: if a firewall_block was in the actions, confirm the rule exists
        has_block = any(a.get("action_type") == "firewall_block" for a in actions)
        if has_block:
            _, rc = await self._run_shell(f"iptables -C INPUT -s {src_ip} -j DROP 2>/dev/null")
            block_applied = (rc == 0)
            await emit_trace(
                alert_id=alert_id, event_type="verification_check", agent="executor",
                action=f"Firewall block rule check for {src_ip}: {'present' if block_applied else 'MISSING'}",
                rationale="Verified iptables rule exists" if block_applied else "Block rule not found — mitigation incomplete"
            )
            if not block_applied:
                return False

        # Check 2: count active connections from src after actions
        out, _ = await self._run_shell(f"ss -tn 2>/dev/null | grep -c '{src_ip}' || echo 0")
        try:
            conn_count = int(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            conn_count = 0

        await emit_trace(
            alert_id=alert_id, event_type="verification_check", agent="executor",
            action=f"Active connections from {src_ip}: {conn_count}",
            rationale=f"{'No' if conn_count == 0 else str(conn_count)} active connections remaining from source IP."
        )

        return conn_count == 0 or has_block

    # ── Re-plan ────────────────────────────────────────────────────────────────

    async def _trigger_replan(
        self, alert_id: str, failed_plan_id: str,
        results: list, approved_by: str, attempt: int
    ):
        """Publish a replan-requests message so the orchestrator generates new plans."""
        await self._update_incident_status(alert_id, "plans_generated")
        if not self._producer:
            return
        payload = {
            "alert_id":       alert_id,
            "failed_plan_id": failed_plan_id,
            "failure_summary": f"{sum(1 for r in results if r['status']=='failed')}/{len(results)} actions failed",
            "replan_attempt": attempt,
            "requested_by":   approved_by,
        }
        self._producer.produce(
            "replan-requests",
            key=alert_id.encode(),
            value=json.dumps(payload).encode()
        )
        self._producer.flush(5.0)
        logger.info("Re-plan requested for alert %s (attempt %d)", alert_id, attempt)

    # ── DB helpers ────────────────────────────────────────────────────────────

    async def _fetch_alert_context(self, alert_id: str) -> dict:
        try:
            import asyncpg
            conn = await asyncpg.connect(os.getenv(
                "DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel"
            ))
            try:
                row = await conn.fetchrow(
                    "SELECT classification, src_ip::text, dst_ip::text, dst_port, anomaly_score "
                    "FROM incidents WHERE alert_id = $1", alert_id
                )
                return dict(row) if row else {}
            finally:
                await conn.close()
        except Exception as e:
            logger.warning("Could not fetch alert context: %s", e)
            return {}

    async def _fetch_alert_status(self, alert_id: str) -> str:
        try:
            import asyncpg
            conn = await asyncpg.connect(os.getenv(
                "DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel"
            ))
            try:
                row = await conn.fetchrow(
                    "SELECT approval_status FROM incidents WHERE alert_id=$1", alert_id
                )
                return row["approval_status"] if row else "unknown"
            finally:
                await conn.close()
        except Exception as e:
            logger.warning("Could not fetch alert status: %s", e)
            return "unknown"

    async def _update_incident_status(self, alert_id: str, status: str, results: list | None = None):
        try:
            import asyncpg
            conn = await asyncpg.connect(os.getenv(
                "DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel"
            ))
            try:
                if status == "closed":
                    any_simulated = results and any(r.get("simulated") for r in results)
                    exec_status = "simulated" if any_simulated else "completed"
                    await conn.execute(
                        "UPDATE incidents SET approval_status='closed', "
                        "execution_status=$2, executed_at=NOW() WHERE alert_id=$1",
                        alert_id, exec_status
                    )
                elif status == "execution_failed":
                    # Keep the alert in History (closed) so it doesn't reappear in Active.
                    # execution_status='failed' tells the UI why it didn't fully succeed.
                    await conn.execute(
                        "UPDATE incidents SET approval_status='closed', "
                        "execution_status='failed', executed_at=NOW() WHERE alert_id=$1",
                        alert_id
                    )
                else:
                    await conn.execute(
                        "UPDATE incidents SET approval_status=$2 WHERE alert_id=$1",
                        alert_id, status
                    )
                logger.info("Alert %s → %s", alert_id, status)
            finally:
                await conn.close()
        except Exception as e:
            logger.error("DB status update failed: %s", e)

    async def _publish_results(self, alert_id: str, results: list, verified: bool):
        if not self._producer:
            return
        payload = {
            "alert_id":  alert_id,
            "results":   results,
            "verified":  verified,
            "status":    "closed" if verified else "execution_failed",
            "executed_at": datetime.now(timezone.utc).isoformat()
        }
        self._producer.produce(
            "action-results",
            key=alert_id.encode(),
            value=json.dumps(payload, default=str).encode()
        )
        self._producer.flush(5.0)
