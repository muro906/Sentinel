# Sentinel – Sprint 1 Code Guide
## Day 1 Morning: Infrastructure, Models, and Sub-Agents

---

## Table of Contents

1. [Infrastructure (Docker Services)](#1-infrastructure)
2. [Database Schema](#2-database-schema)
3. [NVD Sync Script](#3-nvd-sync-script)
4. [Asset Inventory Seeding](#4-asset-inventory-seeding)
5. [Pydantic Data Models](#5-pydantic-data-models)
6. [Kafka Consumer/Producer](#6-kafka-consumerproducer)
7. [Redis State Management](#7-redis-state-management)
8. [Base Agent Class](#8-base-agent-class)
9. [CVE Lookup Agent](#9-cve-lookup-agent)
10. [Asset Discovery Agent](#10-asset-discovery-agent)
11. [Alert Simulator (Testing)](#11-alert-simulator)

---

## 1. Infrastructure

**File:** `docker-compose.yml` (extended)

Three new services added to the existing Kafka/Zeek stack:

### PostgreSQL (pgvector/pgvector:pg16)
- **Purpose:** Stores CVE entries, asset inventory, incident history, and reasoning traces.
- **Why pgvector:** Includes the `vector` extension for optional semantic similarity search on CVE descriptions (future enhancement).
- **Health check:** `pg_isready` ensures dependent services wait until PostgreSQL accepts connections.
- **Volume:** `pgdata` persists database between container restarts.
- **Migrations:** SQL files in `database/migrations/` are auto-executed on first start via Docker's `/docker-entrypoint-initdb.d` mount.

### Redis 7 (redis:7-alpine)
- **Purpose:** Agent task queues (Streams), result caching (Hash), session state (Hash+TTL), and real-time reasoning event stream.
- **Why Redis Streams:** Provides ordered, persistent message logs with consumer group semantics — ideal for task dispatch to sub-agents without the overhead of a full message broker.
- **Config:** `--appendonly yes` enables AOF persistence. `--maxmemory 256mb` with `allkeys-lru` eviction prevents unbounded memory growth.

### Ollama (ollama/ollama:latest)
- **Purpose:** Local LLM serving. Runs Mistral 7B Instruct for the Planning Agent.
- **Why Ollama:** Single binary, no GPU runtime required (runs on CPU for dev), exposes OpenAI-compatible API at `http://ollama:11434`.
- **Volume:** `ollama-models` caches downloaded model weights.
- **First run:** After `docker compose up`, run `docker exec sentinel-ollama ollama pull mistral:7b-instruct-v0.3-q4_K_M` to download the model.

### Orchestrator (custom build)
- **Purpose:** The agentic layer container running the LangGraph state machine.
- **Dependencies:** Waits for Kafka, Redis, PostgreSQL, and Ollama to be healthy before starting.
- **Environment:** All connection URLs passed via env vars for 12-factor compliance.

---

## 2. Database Schema

**Files:** `database/migrations/001-004.sql`

### 001_create_cve_entries.sql
Creates the CVE table with:
- **Core fields:** `cve_id`, `description`, `cvss_v3_score`, `severity`
- **Attack characteristics:** `attack_vector`, `attack_complexity`, `privileges_required` — used by the CVE agent to match traffic patterns to vulnerability profiles
- **Full-text search:** A `tsvector` column auto-populated via trigger concatenating `cve_id + description + vendor + product`. GIN index enables fast `@@` queries.
- **Vector embedding:** `vector(384)` column for future semantic search via all-MiniLM-L6-v2. IVFFlat index for approximate nearest neighbor.
- **The trigger** (`update_cve_search_vector`) fires on INSERT/UPDATE, so the search index is always current.

### 002_create_assets.sql
Three tables modeling network topology:
- **`assets`** — Machines on the network. Key field: `criticality_tier` (1-5) directly influences orchestrator priority scoring.
- **`services`** — Port/software/version per asset. Used to match CVEs to specific installed software.
- **`network_zones`** — Logical segmentation with `trust_level` (1-5). Determines zone exposure factor in blast radius calculation.
- **`asset_dependencies`** — Directed graph of which assets depend on which. Used for blast radius: if A is compromised, downstream B and C are affected.

### 003_create_incidents.sql
Incident log table storing the full lifecycle:
- JSONB columns (`feature_vector`, `cve_matches`, `plans_generated`) provide flexible storage for complex nested data
- Indexed by `classification` and `dst_port` so the Planning Agent can quickly find similar historical incidents for few-shot LLM context

### 004_create_reasoning_traces.sql
One row per reasoning step per alert. Key columns:
- **`rationale`** — THE field the analyst reads: plain-English explanation of WHY
- **`full_input` / `full_output`** — JSONB blobs for drill-down (e.g., full LLM prompt text)
- Indexed by `(alert_id, timestamp)` for fast chronological trace retrieval

---

## 3. NVD Sync Script

**File:** `scripts/sync_nvd.py`

### What it does
Fetches CVE data from the NIST NVD REST API v2.0 and upserts into PostgreSQL.

### Key design decisions
- **Paginated fetching:** NVD API returns max 2000 results per page. Script loops with `startIndex` offset until all results consumed.
- **Upsert logic:** `INSERT ... ON CONFLICT (cve_id) DO UPDATE` — existing CVEs get fresh data, new ones are inserted. Idempotent.
- **Rate limiting:** 6 seconds between requests without API key (NVD enforcement). 0.6 seconds with key.
- **Incremental sync:** Default mode fetches only CVEs modified in the last 7 days. `--full` flag syncs everything (200,000+ CVEs, takes hours).
- **CPE parsing:** Extracts `affected_vendor` and `affected_product` from CPE match strings for fast product-based lookups.

### Running it
```bash
# First time — seed with last 30 days of CVEs
DATABASE_URL=postgresql://sentinel:sentinel_dev@localhost:5432/sentinel \
  python scripts/sync_nvd.py --days 30

# Daily cron (in production)
0 2 * * * /app/scripts/sync_nvd.py --days 2
```

---

## 4. Asset Inventory Seeding

**File:** `database/seed/seed_assets.py`

### What it does
Populates PostgreSQL with sample assets matching the IPs in `capture/generate_sample.py`:
- **10.0.0.0/24 (DMZ):** Web servers (`web-prod-01`, `web-prod-02`), API gateway, DNS resolver
- **192.168.1.0/24 (Internal):** Developer workstations, database server, auth server
- **172.16.0.0/16 (External):** Not seeded (attacker range — the CVE agent recognizes these as external)

### Why this matters
When the alert simulator sends a port scan from `172.16.0.55 → 10.0.0.1:22`, the Asset Discovery Agent resolves `10.0.0.1` to:
- hostname: `web-prod-01`
- criticality: tier 2 (high)
- services: openssh 9.5p1, nginx 1.24.0
- zone: DMZ (trust_level=2, exposure_factor=1.5)
- dependents: `api-gateway` (critical)
- blast_radius: 4 × (1 + 1) × 1.5 = **12.0**

This blast radius directly influences the Planning Agent's confidence and plan aggression.

---

## 5. Pydantic Data Models

**Directory:** `agentic/models/`

### AnomalyAlert (`alert.py`)
The INPUT to the agentic layer. Mirrors what Layer 2 publishes to `anomaly-alerts`:
- `anomaly_score` (0-1): ensemble confidence
- `classification`: attack type enum (port_scan, data_exfiltration, etc.)
- `feature_vector`: nested CESSNET feature schema (same as Layer 1 output)
- `model_votes`: which ML models flagged this and with what confidence

### CVEMatch (`cve.py`)
OUTPUT of the CVE Lookup Agent. Links a CVE to the alert with:
- `matched_signature`: what traffic feature matched (e.g., "dst_port=22, service=openssh")
- `match_confidence`: computed relevance score (0-1)
- `match_rationale`: plain-English explanation for the analyst

### AssetInfo (`asset.py`)
OUTPUT of the Asset Discovery Agent. Complete asset profile:
- `blast_radius`: float — the key impact metric
- `downstream_dependents`: what breaks if this asset is compromised
- `network_zone`: where this asset sits in the network topology

### ExecutionPlan / PlanSet (`plan.py`)
OUTPUT of the Planning Agent:
- `PlanSet`: contains 2-3 plans with different aggression levels
- Each `ExecutionPlan` has: `confidence`, `risk_level`, `automation_tier`, `actions[]`
- Each `Action` has: `type`, `target`, `params`, `rationale`, `reversible`

### ReasoningEvent (`reasoning.py`)
The transparency layer. Every agent step produces one:
- `event_type`: enum (23 types covering full lifecycle)
- `rationale`: THE field the analyst reads
- `full_input` / `full_output`: expandable detail for drill-down

### ThreatBundle (`threat_bundle.py`)
Aggregated context assembled by the orchestrator. Combines:
- Original alert + CVE matches + affected assets + historical incidents
- Computed risk metadata: `priority`, `max_cvss`, `has_active_exploit`, `total_blast_radius`
- `compute_risk_metadata()`: deterministic priority calculation

---

## 6. Kafka Consumer/Producer

**Directory:** `agentic/kafka/`

### Consumer (`consumer.py`)
- **Topics:** Subscribes to `anomaly-alerts` + `action-results`
- **Consumer group:** `sentinel-orchestrator` — ensures each alert processed once even with multiple replicas
- **Manual commit:** Offsets committed only AFTER orchestrator confirms processing (at-least-once semantics)
- **Topic auto-creation:** Creates all 4 topics on startup (idempotent)
- **Error handling:** Invalid JSON messages logged and skipped (dead-letter pattern)

### Producer (`producer.py`)
- **Topic:** Publishes to `execution-plans`
- **Key:** Alert ID — all plans for one alert go to same partition (ordering guarantee)
- **Acks:** `all` — waits for all replicas to confirm (durability over speed)
- **Flush:** Immediate flush after each publish — plans are latency-sensitive

---

## 7. Redis State Management

**Directory:** `agentic/state/`

### redis_client.py
Async connection pool (singleton) using `redis.asyncio`. All agents share one pool with 20 max connections.

### task_queue.py (Redis Streams)
Implements producer/consumer pattern for sub-agent dispatch:
- `dispatch_task()` → XADD to `agent-tasks:{agent_name}`
- `consume_task()` → XREADGROUP (blocking read with consumer group)
- `acknowledge_task()` → XACK (removes from pending)

Why Streams over pub/sub: Streams are persistent, support consumer groups (scalability), and track pending messages (reliability).

### result_store.py (Redis Hash)
Per-incident result aggregation:
- Key: `results:{alert_id}` → Hash mapping `agent_name → JSON result`
- Tracks `_completed_agents` field for completion detection
- TTL: 1 hour auto-cleanup
- `all_agents_complete()`: orchestrator polls this to know when to proceed

### session.py (Redis Hash + TTL)
Per-incident lifecycle tracking:
- Key: `session:{alert_id}` → current state, timestamps, priority
- **Deduplication:** `dedup:{classification}:{src_ip}` with 5-minute TTL — prevents processing the same attack pattern twice within a window
- `create_session()` uses HSETNX for atomic duplicate detection

---

## 8. Base Agent Class

**File:** `agentic/agents/base.py`

### Design Pattern: Template Method
The `BaseAgent` abstract class implements the execution lifecycle (template), while subclasses provide the specific logic via `_process()`.

### What the base class handles automatically:
1. **Timeout enforcement** — `asyncio.wait_for()` with configurable timeout (default 30s)
2. **Retry with exponential backoff** — configurable max retries, delay doubles each attempt
3. **Reasoning event emission** — automatically emits:
   - `AGENT_DISPATCHED` at start
   - `AGENT_RESULT` on success (with duration + output summary)
   - `AGENT_TIMEOUT` / `AGENT_ERROR` on failure
4. **Graceful degradation** — on failure, returns error dict instead of raising. Orchestrator proceeds with partial results.

### Why this matters for the analyst:
Even if an agent fails, the reasoning trace shows WHAT it tried, HOW LONG it ran, and WHY it failed — full transparency.

---

## 9. CVE Lookup Agent

**File:** `agentic/agents/cve_lookup.py`

### Four-step process:

#### Step 1: Extract Signatures
Analyzes the feature vector and produces signature hypotheses:

| Traffic Feature | Signature Type | Example |
|---|---|---|
| `dst_port=22` | `service_vuln` | "openssh" |
| `conn_state=S0` | `reconnaissance` | "port_scan" |
| `conn_state=RSTO` | `exploit_attempt` | "remote code execution" |
| `ssl_version=SSLv3` | `weak_tls` | "POODLE, BEAST" |
| `dns_query=<base64>.evil.com` | `dns_attack` | "DNS tunneling" |
| `bytes_ratio > 5.0` | `exfiltration` | "C2 data theft" |

#### Step 2: Build Queries
Each signature maps to a different query strategy:
- `service_vuln` → `search_by_product(product="openssh")`
- `reconnaissance` → `search_by_attack_pattern(vector=NETWORK, privs=NONE)`
- All signatures also get keyword search as fallback

#### Step 3: Search Database
Runs queries against PostgreSQL. Multiple strategies per signature — merges all results.

#### Step 4: Score & Deduplicate
Confidence formula:
```
confidence = (cvss_weight × 0.4) + (exploit_bonus × 0.3) + (signature_match × 0.3)
```
- `cvss_weight`: normalized CVSS score (0-1)
- `exploit_bonus`: 0.8 if known exploit exists, 0.2 otherwise
- `signature_match`: quality of the signature match (service_vuln=0.9, generic=0.4)

Returns top 5 CVEs sorted by confidence. Each includes a `match_rationale` explaining WHY it was matched.

---

## 10. Asset Discovery Agent

**File:** `agentic/agents/asset_discovery.py`

### Three-step process:

#### Step 1: Resolve IPs
Looks up both `src_ip` and `dst_ip` in the PostgreSQL asset inventory:
- Found → full asset profile (hostname, OS, services, zone)
- Not found → zone detection via CIDR matching (determines if internal unknown or external attacker)

#### Step 2: Enrich
For each resolved asset:
- Fetches running services (what software is exposed)
- Gets network zone (trust boundaries)
- Finds downstream dependents (what breaks if compromised)

#### Step 3: Calculate Blast Radius
```
blast_radius = (6 - criticality_tier) × (1 + critical_dependents) × zone_exposure_factor
```

| Criticality | Factor | Zone Trust | Exposure |
|---|---|---|---|
| 1 (mission-critical) | 5 | 1 (untrusted) | 2.0× |
| 2 (high) | 4 | 2 (DMZ) | 1.5× |
| 3 (medium) | 3 | 3 (internal) | 1.0× |
| 4 (low) | 2 | 4 (management) | 0.7× |
| 5 (negligible) | 1 | 5 (restricted) | 0.5× |

Example: `web-prod-01` (criticality=2, 1 critical dependent, DMZ zone):
```
blast_radius = (6-2) × (1+1) × 1.5 = 4 × 2 × 1.5 = 12.0
```

This high blast radius signals to the Planning Agent that aggressive response is warranted.

---

## 11. Alert Simulator

**File:** `scripts/simulate_alerts.py`

### Purpose
Since Layer 2 (Hybrid Detection) isn't built yet, this script produces synthetic alerts to the `anomaly-alerts` Kafka topic for end-to-end testing.

### Three alert types:
1. **Port scan** — 172.16.0.55 → 10.0.0.1:22, conn_state=S0, score=0.91
2. **Data exfiltration** — 192.168.1.12 → external:443, high bytes_ratio, score=0.85
3. **DNS tunneling** — 192.168.1.50 → 10.0.0.53:53, base64-encoded query, score=0.78

### Usage
```bash
# Single alert
python scripts/simulate_alerts.py --type port_scan

# Burst of mixed alerts (for load testing)
python scripts/simulate_alerts.py --burst 10
```

---

## File Index

| File | Purpose |
|---|---|
| `docker-compose.yml` | Infrastructure orchestration (extended) |
| `database/migrations/001_create_cve_entries.sql` | CVE table + full-text + vector indexes |
| `database/migrations/002_create_assets.sql` | Assets, services, zones, dependencies |
| `database/migrations/003_create_incidents.sql` | Incident history for LLM context |
| `database/migrations/004_create_reasoning_traces.sql` | Agent decision audit log |
| `database/seed/seed_assets.py` | Sample network topology matching sample.pcap |
| `scripts/sync_nvd.py` | NVD → PostgreSQL CVE sync |
| `scripts/simulate_alerts.py` | Mock alert publisher for testing |
| `agentic/models/alert.py` | AnomalyAlert schema (input) |
| `agentic/models/cve.py` | CVEMatch schema (CVE agent output) |
| `agentic/models/asset.py` | AssetInfo schema (asset agent output) |
| `agentic/models/plan.py` | ExecutionPlan, PlanSet, Action schemas |
| `agentic/models/reasoning.py` | ReasoningEvent schema (transparency) |
| `agentic/models/threat_bundle.py` | ThreatBundle (aggregated LLM input) |
| `agentic/kafka/consumer.py` | Kafka consumer (anomaly-alerts, action-results) |
| `agentic/kafka/producer.py` | Kafka producer (execution-plans) |
| `agentic/state/redis_client.py` | Async Redis connection pool |
| `agentic/state/task_queue.py` | Redis Streams task dispatch |
| `agentic/state/result_store.py` | Per-incident result aggregation |
| `agentic/state/session.py` | Session lifecycle + deduplication |
| `agentic/agents/base.py` | BaseAgent (timeout, retry, reasoning) |
| `agentic/agents/cve_lookup.py` | CVE Lookup Agent |
| `agentic/agents/asset_discovery.py` | Asset Discovery Agent |
| `agentic/db/connection.py` | asyncpg connection pool |
| `agentic/db/cve_repository.py` | CVE database queries |
| `agentic/db/asset_repository.py` | Asset database queries |
| `agentic/reasoning/emitter.py` | Reasoning event → Redis Stream |
| `agentic/Dockerfile` | Container build for orchestrator |
| `agentic/requirements.txt` | Python dependencies |

---

## How to Run (Development)

```bash
# 1. Start infrastructure
docker compose up -d postgres redis kafka zookeeper ollama

# 2. Wait for health checks to pass
docker compose ps  # all should show "healthy"

# 3. Pull the LLM model (first time only, ~4GB)
docker exec sentinel-ollama ollama pull mistral:7b-instruct-v0.3-q4_K_M

# 4. Seed the database
DATABASE_URL=postgresql://sentinel:sentinel_dev@localhost:5432/sentinel \
  python database/seed/seed_assets.py

# 5. Sync some CVEs (last 7 days)
DATABASE_URL=postgresql://sentinel:sentinel_dev@localhost:5432/sentinel \
  python scripts/sync_nvd.py

# 6. Send a test alert
python scripts/simulate_alerts.py --type port_scan

# 7. Start the orchestrator (next sprint implements main.py)
docker compose up orchestrator
```

---

---

# Day 1 Afternoon: Orchestrator + Planning Agent + LLM

---

## 12. Orchestrator State

**File:** `agentic/orchestrator/state.py`

A `TypedDict` capturing the full incident lifecycle. LangGraph passes this between nodes — each node reads what it needs and returns a partial dict to update:

- **Alert Input** — `alert_id`, `alert_raw`, `alert_timestamp`
- **Triage** — `classification`, `anomaly_score`, `priority`, `priority_score`, `is_duplicate`
- **Sub-Agent Results** — `cve_matches`, `affected_assets`, `agents_completed`, `agents_timed_out`
- **Threat Bundle** — `threat_bundle`, `max_cvss`, `total_blast_radius`, `has_active_exploit`
- **Planning** — `llm_prompt`, `llm_response`, `plans`, `plan_set`, `best_plan_confidence`
- **Approval** — `approval_status`, `approved_plan_id`, `approved_actions`, `approved_by`
- **Execution** — `execution_results`, `execution_status`, `failed_actions`
- **Control Flow** — `current_node`, `error`, `should_replan`

Using `total=False` makes all fields optional — nodes only set what they're responsible for.

---

## 13. Orchestrator Configuration

**File:** `agentic/orchestrator/config.py`

Centralized thresholds and timeouts. All overridable via environment variables:

| Config | Default | Purpose |
|---|---|---|
| `AGENT_TIMEOUT` | 30s | Max time per sub-agent call |
| `MIN_ANOMALY_SCORE` | 0.5 | Below this → alert is dropped |
| `DEDUP_WINDOW` | 300s | Same classification+src_ip → duplicate |
| `NUM_PLANS` | 3 | How many plans the LLM generates |
| `LLM_TEMPERATURE` | 0.7 | Diversity in plan generation |
| `APPROVAL_TIMEOUT` | 600s | Escalate if no analyst response |

### Automation Tiers

Maps best plan confidence → required human involvement:

| Confidence | Tier | Behaviour |
|---|---|---|
| ≥ 0.95 | `auto_execute` | Fully automatic |
| ≥ 0.85 | `auto_recommend` | Pre-selected, analyst confirms |
| ≥ 0.70 | `suggest` | Analyst reviews before approval |
| ≥ 0.50 | `advise` | Advisory only, analyst decides |
| < 0.50 | `escalate` | Senior analyst required |

---

## 14. Graph Nodes

**File:** `agentic/orchestrator/nodes.py`

Each function is a LangGraph node. Takes `OrchestratorState`, returns partial update:

### Node 1: `receive_alert`
- Parses raw Kafka JSON into `AnomalyAlert` Pydantic model
- Extracts key fields (IPs, port, classification) into state
- Creates Redis session for lifecycle tracking
- Emits `ALERT_RECEIVED` reasoning event

### Node 2: `triage`
- **Deduplication:** Checks Redis `dedup:{classification}:{src_ip}` key (5-min window). If found → emits `DUPLICATE_DETECTED`, returns `is_duplicate=True`.
- **Priority scoring:** `anomaly_score × classification_weight × 5.0`
  - Classification weights: `exploit_attempt=2.0`, `data_exfiltration=1.5`, `port_scan=0.8`
- **Priority mapping:** score ≥8 → critical, ≥5 → high, ≥2.5 → medium, else → low
- Emits `TRIAGE_DECISION` with full scoring breakdown

### Node 3: `dispatch_agents`
- Builds `task_data` from state (IPs, port, classification, conn_state, etc.)
- Dispatches CVE Lookup + Asset Discovery agents **in parallel** via `asyncio.gather`
- Each agent runs with timeout + retry (handled by `BaseAgent`)
- Collects results, handles exceptions, tracks timeouts
- Stores results in Redis (`result_store`) for persistence
- Does NOT emit reasoning events directly — sub-agents emit their own

### Node 4: `aggregate`
- Merges CVE matches + asset info + original alert into `ThreatBundle`
- Calls `compute_risk_metadata()` to derive:
  - `priority` (from CVSS + asset criticality + anomaly score)
  - `max_cvss`, `total_blast_radius`, `has_active_exploit`
- Emits `CONTEXT_BUILT` reasoning event with risk summary

### Node 5: `generate_plans`
- Calls `context_builder.build_prompt()` with the ThreatBundle
- Emits `LLM_PROMPT` event (full prompt text available in `full_input`)
- Calls `llm_client.generate_plans()` — sends to Ollama
- Emits `LLM_RESPONSE` event (raw response + parsed plans in `full_output`)
- Calls `plan_ranker.rank_plans()` — scores each plan
- Emits `PLAN_SCORED` for each plan with confidence and risk assessment
- Builds `PlanSet` with all plans + context references

### Node 6: `publish_plans`
- Determines automation tier from best plan's confidence
- Emits `PLAN_PUBLISHED` reasoning event explaining the tier decision
- Publishes `PlanSet` to Kafka `execution-plans` topic
- Dashboard consumes this topic and presents plans to the analyst

### Node 7: `handle_failure`
- Triggered when execution layer reports failures
- Emits `REPLAN_TRIGGERED` event
- Sets `should_replan=True` → routing function sends back to `generate_plans`

### Routing Functions
- `should_continue_after_triage`: skip duplicates and low-score alerts
- `should_replan_or_end`: loop back to planning on failure, or end

---

## 15. LangGraph Definition

**File:** `agentic/orchestrator/graph.py`

Wires nodes into the state machine:

```
receive_alert → triage ─┬─ [duplicate/low score] → END
                         └─ dispatch_agents → aggregate → generate_plans → publish_plans → END
                                                              ↑
                                              handle_failure ─┘ (re-plan loop)
```

Key design decisions:
- **Approval is external:** The graph ends at `publish_plans`. Approval and execution are triggered by Kafka messages from the dashboard/execution layer. This keeps the orchestrator non-blocking — it publishes plans and immediately starts processing the next alert.
- **Re-plan loop:** `handle_failure → generate_plans` creates a feedback loop for execution failures.
- **Entry point:** `receive_alert` — invoked with `graph.ainvoke({"alert_raw": alert_dict})`

---

## 16. Context Builder

**File:** `agentic/planning/context_builder.py`

Transforms a ThreatBundle dict into an LLM prompt:
- Loads `prompts/threat_response.jinja2` template (falls back to inline if file missing)
- Renders with full alert details, CVE matches, affected assets, risk summary
- Prompt follows Mistral `[INST]...[/INST]` format
- Instructs the LLM to generate exactly 3 plans (conservative, moderate, aggressive)
- Specifies exact JSON output schema for structured parsing

---

## 17. LLM Client

**File:** `agentic/planning/llm_client.py`

OpenAI-compatible async client pointing at Ollama:
- Creates `AsyncOpenAI` client with base_url = `http://ollama:11434/v1`
- Sends prompt as a chat message (`user` role)
- Parses response JSON (handles code fences, raw JSON, regex fallback)
- **Fallback plan:** If LLM fails entirely, generates a minimal conservative plan that notifies the security team and starts deep inspection — analyst always gets SOMETHING.

---

## 18. Plan Ranker

**File:** `agentic/planning/plan_ranker.py`

Scores each plan with a composite formula:

```
confidence = (model_confidence × 0.4) + (cve_match_score × 0.3) + (asset_criticality_score × 0.3)
```

Risk assessment per plan:
- Calculates `max_destructiveness` from actions (isolate_host=0.9, notify=0.05)
- Counts irreversible actions (penalty)
- Risk = destructiveness × (0.5 + false_positive_chance × 0.5)
- Maps risk score → risk_level (critical/high/medium/low)
- Maps confidence → automation_tier via `OrchestratorConfig`

---

## 19. Prompt Templates

**Directory:** `agentic/planning/prompts/`

### `threat_response.jinja2`
Full planning prompt with sections:
- Alert details (IPs, ports, protocol, connection state, TLS, DNS)
- Model votes from ensemble
- CVE matches (ID, CVSS, exploit status, match rationale)
- Affected assets (hostname, criticality, services, blast radius, dependents)
- Risk summary (priority, max CVSS, blast radius, exploit flag)
- Historical incidents (if available)
- Output format instructions (strict JSON schema)

### `replan.jinja2`
Used after execution failure. Includes:
- Original plan that failed
- Per-action execution results (success/failure/error)
- Instructions to generate revised plan working around failures

---

## 20. Reasoning Trace Persistence

**File:** `agentic/reasoning/trace.py`

Background task that reads reasoning events from Redis Streams and batch-inserts into PostgreSQL:
- Scans for all `reasoning:*` streams
- Reads new events via `XREAD` (blocking)
- Batch-inserts every 50 events or 5 seconds
- `ON CONFLICT DO NOTHING` for idempotency
- Runs as `asyncio.create_task()` in the orchestrator process

---

## 21. Main Entry Point

**File:** `agentic/main.py`

The `Orchestrator` class coordinates everything:
1. Compiles the LangGraph graph
2. Connects Kafka consumer (subscribes to `anomaly-alerts` + `action-results`)
3. Starts trace persister background task
4. Main loop: poll Kafka → invoke graph → commit offset
5. Signal handling: SIGINT/SIGTERM → graceful shutdown

For each alert:
```python
result = await self._graph.ainvoke({"alert_raw": alert_data})
```
The entire pipeline (receive → triage → dispatch → aggregate → plan → publish) runs in one graph invocation.

---

## Updated File Index

| File | Purpose |
|---|---|
| `agentic/orchestrator/state.py` | TypedDict state flowing through graph |
| `agentic/orchestrator/config.py` | Thresholds, timeouts, automation tiers |
| `agentic/orchestrator/nodes.py` | 7 graph nodes + 2 routing functions |
| `agentic/orchestrator/graph.py` | LangGraph state machine wiring |
| `agentic/planning/context_builder.py` | ThreatBundle → Jinja2 → LLM prompt |
| `agentic/planning/llm_client.py` | Async Ollama client + JSON parsing |
| `agentic/planning/plan_ranker.py` | Confidence scoring + risk assessment |
| `agentic/planning/prompts/threat_response.jinja2` | Main planning prompt |
| `agentic/planning/prompts/replan.jinja2` | Re-planning prompt |
| `agentic/reasoning/trace.py` | Redis → PostgreSQL batch persister |
| `agentic/agents/registry.py` | Agent name → class mapping |
| `agentic/main.py` | Entry point, Kafka loop, shutdown |

---

---

# Day 2: Execution Layer + Incident Lifecycle

---

## 22. Base Executor

**File:** `agentic/execution/base_executor.py`

Abstract base for all action executors. Each executor wraps an infrastructure API call with a five-stage lifecycle:

1. **Validate** — pre-flight checks (protected IPs, required params)
2. **Execute** — call the infrastructure API/CLI
3. **Verify** — confirm the action took effect
4. **Rollback** — undo on verification failure (if reversible)
5. **Reason** — emit events at every stage for full transparency

Key features:
- **Dry-run mode** — logs what WOULD happen without touching anything. Enabled by default via `DRY_RUN=true` env var.
- Returns `ActionResult` Pydantic model with status, output, error, duration.
- Never throws — failures are captured as result objects so the router can continue with remaining actions.

---

## 23. Action Router

**File:** `agentic/execution/router.py`

Routes approved actions to the correct executor:
- Maintains an `_EXECUTOR_REGISTRY` dict mapping action type → executor instance
- `execute_plan()` runs actions sequentially (order matters — block before isolate)
- `stop_on_failure=True` skips remaining actions if one fails (prevents cascading damage)
- Emits `EXECUTION_STARTED` and `EXECUTION_COMPLETED`/`EXECUTION_FAILED` reasoning events

`init_executors(dry_run)` registers all 9 built-in executors at startup.

---

## 24. Executors (7 action types, 9 classes)

**Directory:** `agentic/execution/executors/`

### `firewall.py` — FirewallBlockExecutor + FirewallUnblockExecutor
- Blocks inbound/outbound traffic for an IP or CIDR
- Validates against protected management IPs (configurable via `PROTECTED_IPS`)
- Supports `simulate` (default) and `iptables` adapters via `FIREWALL_ADAPTER` env
- UnblockExecutor removes rules (used in rollback or plan completion)

### `isolate.py` — IsolateHostExecutor + RestoreHostExecutor
- Most destructive action — quarantines host by VLAN reassignment
- Validates against `PROTECTED_HOSTS` (DNS, DC, management — never isolate)
- Verification: simulates ping test failure confirmation
- Rollback: restore original VLAN
- RestoreHostExecutor for explicit reconnection

### `patch.py` — PatchExecutor
- Triggers security patch for a specific CVE or package
- Requires either `cve_id` or `package` in params
- Verification: checks package version post-patch
- **Not reversible** — rollback requires snapshot restoration

### `notify.py` — NotifyExecutor
- Multi-channel: Slack webhook, PagerDuty, email, Teams, log fallback
- Least destructive — safe to auto-execute
- Real Slack/PagerDuty integration when webhook URLs are configured
- Falls back to simulation logging in dev

### `inspect.py` — DeepInspectExecutor
- Starts extended packet capture for manual analysis
- Duration limit: 1–1440 minutes
- Used in conservative plans to gather evidence before acting

### `rate_limit.py` — RateLimitExecutor
- Throttles traffic (requests/sec or bandwidth cap)
- Less disruptive than full block — allows legitimate traffic
- Reversible: rate limit can be removed

### `credential.py` — CredentialRotateExecutor
- Forces rotation: password, SSH key, API key, TLS cert, DB password, service account
- High impact — can cause brief service outages
- **Not reversible** — old credentials are invalidated
- Verification: tests auth with new credentials

---

## 25. Approval Handler

**File:** `agentic/execution/approval_handler.py`

Bridges the orchestrator (publishes plans) and execution layer (runs actions):

1. Subscribes to `approved-actions` Kafka topic
2. SOC analyst approves a plan on the dashboard → message published
3. Handler deserializes the message → routes to `execute_plan()`
4. Collects `ActionResult` list → publishes each to `action-results` topic
5. Updates incident session state

Also supports `handle_auto_execute()` for plans with confidence ≥ 95% where the automation tier allows it.

Runs as a background `asyncio.Task` inside the orchestrator process.

---

## 26. Incident Repository

**File:** `agentic/db/incident_repository.py`

Full incident lifecycle in PostgreSQL:
- `create_incident()` — on alert receive
- `update_incident_plans()` — after LLM generates plans
- `update_incident_approval()` — after analyst approves
- `update_incident_execution()` — after actions complete
- `close_incident()` — with outcome summary
- `find_similar_incidents()` — historical query for LLM few-shot context
- `list_active_incidents()` — for dashboard display

The `find_similar_incidents()` function returns closed incidents with matching classification and port, ordered by recency. These are injected into the LLM prompt so the model can see how similar threats were handled before (few-shot context).

---

## Complete File Index

### Infrastructure
| File | Purpose |
|---|---|
| `docker-compose.yml` | PostgreSQL, Redis, Ollama, Kafka, orchestrator |
| `database/migrations/001-004.sql` | CVE, assets, incidents, reasoning_traces tables |
| `database/seed/seed_assets.py` | Sample network topology |
| `scripts/sync_nvd.py` | NVD → PostgreSQL CVE sync |
| `scripts/simulate_alerts.py` | Mock alert publisher |

### Models
| File | Purpose |
|---|---|
| `agentic/models/alert.py` | AnomalyAlert (Layer 2 → Layer 3 input) |
| `agentic/models/cve.py` | CVEEntry, CVEMatch |
| `agentic/models/asset.py` | AssetInfo, ServiceInfo, NetworkZone, AssetDependency |
| `agentic/models/plan.py` | ExecutionPlan, PlanSet, Action, ActionResult |
| `agentic/models/reasoning.py` | ReasoningEvent (30 event types) |
| `agentic/models/threat_bundle.py` | ThreatBundle (aggregated LLM input) |

### Orchestrator
| File | Purpose |
|---|---|
| `agentic/orchestrator/state.py` | OrchestratorState TypedDict |
| `agentic/orchestrator/config.py` | Thresholds, automation tiers |
| `agentic/orchestrator/nodes.py` | 7 graph nodes + 2 routing functions |
| `agentic/orchestrator/graph.py` | LangGraph state machine |
| `agentic/main.py` | Entry point, Kafka loop, shutdown |

### Sub-Agents
| File | Purpose |
|---|---|
| `agentic/agents/base.py` | BaseAgent (timeout, retry, reasoning) |
| `agentic/agents/cve_lookup.py` | CVE Lookup Agent |
| `agentic/agents/asset_discovery.py` | Asset Discovery Agent |
| `agentic/agents/registry.py` | Agent name → class registry |

### Planning
| File | Purpose |
|---|---|
| `agentic/planning/context_builder.py` | ThreatBundle → LLM prompt |
| `agentic/planning/llm_client.py` | Async Ollama client + fallback |
| `agentic/planning/plan_ranker.py` | Confidence scoring + risk assessment |
| `agentic/planning/prompts/threat_response.jinja2` | Main prompt template |
| `agentic/planning/prompts/replan.jinja2` | Re-planning prompt |

### Execution
| File | Purpose |
|---|---|
| `agentic/execution/base_executor.py` | BaseExecutor (validate → execute → verify → rollback) |
| `agentic/execution/router.py` | Action type → executor routing |
| `agentic/execution/approval_handler.py` | Kafka approved-actions → execution |
| `agentic/execution/executors/firewall.py` | Block/unblock IP |
| `agentic/execution/executors/isolate.py` | Quarantine/restore host |
| `agentic/execution/executors/patch.py` | Apply security patch |
| `agentic/execution/executors/notify.py` | Slack, PagerDuty, email, Teams |
| `agentic/execution/executors/inspect.py` | Extended packet capture |
| `agentic/execution/executors/rate_limit.py` | Traffic throttling |
| `agentic/execution/executors/credential.py` | Credential rotation |

### State Management
| File | Purpose |
|---|---|
| `agentic/state/redis_client.py` | Async Redis connection pool |
| `agentic/state/task_queue.py` | Redis Streams task dispatch |
| `agentic/state/result_store.py` | Per-incident result aggregation |
| `agentic/state/session.py` | Session lifecycle + dedup |

### Database
| File | Purpose |
|---|---|
| `agentic/db/connection.py` | asyncpg connection pool |
| `agentic/db/cve_repository.py` | CVE queries (full-text, product, pattern) |
| `agentic/db/asset_repository.py` | Asset/service/zone queries |
| `agentic/db/incident_repository.py` | Incident CRUD + historical queries |

### Reasoning
| File | Purpose |
|---|---|
| `agentic/reasoning/emitter.py` | Event → Redis Stream (real-time) |
| `agentic/reasoning/trace.py` | Redis Stream → PostgreSQL (persistence) |

---

## Architecture Summary

```
┌──────────────────────────────────────────────────────────────────┐
│  Layer 2: Hybrid Detection                                       │
│  (anomaly-alerts Kafka topic)                                    │
└──────────────────┬───────────────────────────────────────────────┘
                   │
    ┌──────────────▼──────────────┐
    │      ORCHESTRATOR (main.py) │
    │  ┌────────────────────────┐ │
    │  │ LangGraph State Machine│ │
    │  │                        │ │
    │  │ receive_alert          │ │
    │  │   │                    │ │
    │  │ triage ──→ [dedup/end] │ │
    │  │   │                    │ │
    │  │ dispatch_agents        │ │  ┌──────────────┐
    │  │   ├─ CVE Lookup ───────┼──┤  PostgreSQL   │
    │  │   └─ Asset Discovery ──┼──┤  (pgvector)   │
    │  │   │                    │ │  └──────────────┘
    │  │ aggregate              │ │
    │  │   │                    │ │  ┌──────────────┐
    │  │ generate_plans ────────┼──┤  Ollama/LLM   │
    │  │   │                    │ │  └──────────────┘
    │  │ publish_plans          │ │
    │  └────────────────────────┘ │  ┌──────────────┐
    │                             ├──┤  Redis        │
    │  ┌────────────────────────┐ │  │  (state +     │
    │  │ Approval Handler       │ │  │   streams)    │
    │  │ (approved-actions →    │ │  └──────────────┘
    │  │  execute_plan →        │ │
    │  │  action-results)       │ │
    │  └────────────────────────┘ │
    │                             │
    │  ┌────────────────────────┐ │
    │  │ Trace Persister        │ │
    │  │ (Redis → PostgreSQL)   │ │
    │  └────────────────────────┘ │
    └─────────────────────────────┘
                   │
    ┌──────────────▼──────────────┐
    │  execution-plans Kafka topic │
    │  → SOC Dashboard (future)   │
    └─────────────────────────────┘
```

---

*Document generated: Sprint 1 — Complete Agentic Layer (51 Python files, 4 SQL migrations, 2 Jinja2 templates)*
