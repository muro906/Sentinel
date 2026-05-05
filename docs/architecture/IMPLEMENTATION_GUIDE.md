# Sentinel – Implementation Guide

> Open-source tooling, detailed implementation outline, and directory structure for the agentic layer.

---

## 1. Open Source Framework & Tooling Stack

### Agent Orchestration

| Component | Tool | License | Why |
|---|---|---|---|
| **Agent Framework** | [LangGraph](https://github.com/langchain-ai/langgraph) | MIT | Graph-based state machine for multi-agent orchestration. Explicit nodes, edges, and conditional routing. Built-in checkpointing for resumable workflows. Better than vanilla LangChain for structured multi-step agents. |
| **Alternative** | [CrewAI](https://github.com/crewAIInc/crewAI) | MIT | Simpler role-based multi-agent if LangGraph feels over-engineered. Less control over state transitions. |
| **Agent Reasoning Trace** | [LangSmith OSS / LangFuse](https://github.com/langfuse/langfuse) | MIT | Full observability of agent reasoning chains. Captures every LLM call, tool use, and decision. Exposes traces via API for dashboard rendering. |

### LLM (Local, Fine-tuned)

| Component | Tool | License | Why |
|---|---|---|---|
| **LLM Serving** | [vLLM](https://github.com/vllm-project/vllm) | Apache 2.0 | High-throughput OpenAI-compatible API server. PagedAttention for efficient memory. Supports quantised models (AWQ, GPTQ). |
| **Alternative Serving** | [Ollama](https://github.com/ollama/ollama) | MIT | Simpler single-binary deployment. Good for dev/testing. Less tunable for production throughput. |
| **Base Model** | [Mistral 7B](https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.3) or [Llama 3.1 8B](https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct) | Apache 2.0 / Meta Community | Strong instruction-following at small size. Fine-tunable on incident response playbooks. |
| **Fine-tuning** | [Unsloth](https://github.com/unslothai/unsloth) | Apache 2.0 | 2x faster QLoRA fine-tuning with 80% less memory. Works with Llama/Mistral. |
| **Structured Output** | [Outlines](https://github.com/dottxt-ai/outlines) or [Instructor](https://github.com/instructor-ai/instructor) | Apache 2.0 / MIT | Guarantees JSON schema compliance from LLM output. No parsing failures. |

### Data & Messaging

| Component | Tool | License | Why |
|---|---|---|---|
| **Message Bus** | [Apache Kafka](https://kafka.apache.org/) (existing) | Apache 2.0 | Already in stack. Durable, auditable inter-layer communication. |
| **Intra-agent State** | [Redis 7](https://redis.io/) + Redis Streams | BSD-3 (Redis ≤7.2) | Task queues, result stores, session state, pub/sub heartbeats. |
| **CVE Database** | [PostgreSQL 16](https://postgresql.org/) + [NVD API mirror](https://nvd.nist.gov/developers/vulnerabilities) | PostgreSQL License | Full-text search on CVE descriptions. Nightly sync via NVD REST API. |
| **Vector Search (optional)** | [pgvector](https://github.com/pgvector/pgvector) | PostgreSQL License | Semantic similarity search on CVE descriptions using embeddings. |
| **Asset Inventory** | PostgreSQL | PostgreSQL License | Hosts, services, network zones. Could integrate with existing CMDB. |

### Observability & Reasoning Transparency

| Component | Tool | License | Why |
|---|---|---|---|
| **Agent Trace UI** | [LangFuse](https://github.com/langfuse/langfuse) | MIT | Self-hosted. Shows full reasoning chain: LLM prompts, tool calls, intermediate outputs. Embeddable trace viewer. |
| **Alternative** | [Phoenix (Arize)](https://github.com/Arize-ai/phoenix) | ELv2 → Apache 2.0 | LLM observability with trace visualization. Good for debugging agent decisions. |
| **Metrics** | [Prometheus](https://prometheus.io/) + [Grafana](https://grafana.com/) | Apache 2.0 | Agent latency, throughput, error rates, LLM token usage. |
| **Logging** | [Structlog](https://github.com/hynek/structlog) | Apache 2.0 | Structured JSON logs from every agent step. Feeds into trace viewer. |

### Dashboard & Human Interface

| Component | Tool | License | Why |
|---|---|---|---|
| **Backend** | [FastAPI](https://fastapi.tiangolo.com/) (existing) | MIT | Already in stack. WebSocket + REST. Async-native. |
| **Frontend** | [React](https://react.dev/) + [shadcn/ui](https://ui.shadcn.com/) + [TailwindCSS](https://tailwindcss.com/) | MIT | Modern component library. Reasoning trace viewer, plan approval cards, real-time updates. |
| **Real-time** | WebSocket (existing pattern) | – | Bidirectional push for alerts, plans, and approval commands. |
| **Reasoning Viewer** | Custom component consuming LangFuse trace API | – | Renders agent thought process as expandable tree with timestamps. |

---

## 2. Agent Reasoning Transparency

The analyst sees the full chain of reasoning for every alert:

```mermaid
flowchart TD
    subgraph TRACE["REASONING TRACE (visible to analyst)"]
        direction TB
        T1["1. Alert Received\n(timestamp, raw features, anomaly_score)"]
        T2["2. Triage Decision\n(priority=HIGH, rationale: 'port scan + high CVSS target')"]
        T3["3. CVE Lookup\n(query: 'openssh dst_port=22 conn_state_S0')\n→ Found: CVE-2024-XXXX (cvss=8.1)"]
        T4["4. Asset Lookup\n(query: dst_ip=10.0.0.1)\n→ Found: web-prod-01, criticality=2, dmz"]
        T5["5. LLM Prompt\n(full prompt text viewable on click)"]
        T6["6. LLM Response\n(raw generation + parsed plans)"]
        T7["7. Confidence Scoring\n(model: 0.87, rationale: 'known CVE + critical asset + active exploit')"]
        T1 --> T2 --> T3 --> T4 --> T5 --> T6 --> T7
    end
```

### What the Analyst Sees per Alert

| UI Element | Content | Source |
|---|---|---|
| **Alert Card** | Anomaly score, classification, src/dst IPs, timestamp | Kafka `anomaly-alerts` |
| **Reasoning Timeline** | Expandable step-by-step trace (see above) | LangFuse trace API or custom event log |
| **CVE Matches** | CVE ID, CVSS score, description, matched signature, exploit availability | CVE Lookup Agent result |
| **Affected Assets** | Hostname, OS, criticality tier, running services, network zone | Asset Discovery Agent result |
| **LLM Prompt** | Full text (expandable) showing what context was fed to the model | Planning Agent context builder |
| **LLM Raw Output** | The actual model generation before parsing | Planning Agent |
| **Plan Cards** | Each plan with actions, confidence, risk level, rationale per action | Plan Ranker output |
| **Approve / Modify / Reject** | Action buttons per plan | WebSocket commands |
| **Execution Status** | Live progress of approved actions | Kafka `action-results` |

### Implementation Approach for Reasoning Traces

```
Option A: LangFuse (recommended for production)
  - Self-host LangFuse via Docker
  - Instrument LangGraph nodes with langfuse.trace()
  - Dashboard fetches traces via LangFuse REST API
  - Renders as expandable tree component

Option B: Custom Event Stream (simpler, tighter integration)
  - Each agent emits structured "reasoning events" to Redis Stream
  - Events: {step, timestamp, agent, action, input, output, rationale}
  - Dashboard consumes stream via WebSocket
  - Renders as live-updating timeline
  - Full control over UX, no external dependency
```

---

## 3. Detailed Implementation Outline (2-Day Sprint)

> Full complexity retained. The AI coding agent handles implementation; this is your reference guide for directing it.

### DAY 1 — Morning (4h): Infrastructure + Models + Agents

| # | Task | Prompt the Agent With | Details |
|---|---|---|---|
| 1.1 | **Docker services** | "Add PostgreSQL (pgvector), Redis 7, Ollama to docker-compose.yml" | Extend existing `docker-compose.yml`. Health checks. Shared network. Environment variables. |
| 1.2 | **Database migrations** | "Create SQL migrations for CVE, assets, incidents, reasoning_traces tables" | `database/migrations/001-004.sql`. Full-text index on CVE descriptions. pgvector column for semantic search. |
| 1.3 | **NVD sync script** | "Create a script to sync CVEs from NVD REST API v2.0 into PostgreSQL" | `scripts/sync_nvd.py`. Paginated fetch. Upsert logic. Full-text + vector index refresh. Run once to seed. |
| 1.4 | **Seed asset inventory** | "Create seed script with sample assets, services, network zones" | `database/seed/seed_assets.py`. 10–20 hosts with varying criticality, services, VLANs. Matches IPs in `generate_sample.py`. |
| 1.5 | **Pydantic models** | "Create all Pydantic models for the agentic layer" | `agentic/models/` — `AnomalyAlert`, `CVEMatch`, `AssetInfo`, `ThreatBundle`, `ExecutionPlan`, `Action`, `PlanSet`, `ApprovedAction`, `ActionResult`, `ReasoningEvent`. All with validators, JSON examples, and serialisation helpers. |
| 1.6 | **Kafka consumers/producers** | "Create Kafka consumer for anomaly-alerts and producer for execution-plans, following existing pattern in ingestion/" | `agentic/kafka/consumer.py`, `producer.py`. Reuse confluent-kafka pattern. Consumer groups. Deserialization to Pydantic models. |
| 1.7 | **Redis client + state** | "Create Redis client with connection pool, task queue (Streams), result store (Hash), session state, reasoning event stream" | `agentic/state/redis_client.py`, `task_queue.py`, `result_store.py`, `session.py`. All async (redis-py with asyncio). |
| 1.8 | **Base agent class** | "Create abstract BaseAgent with execute(), emit_reasoning(), retry, timeout" | `agentic/agents/base.py`. Structured reasoning emission at every step. Configurable timeout + max retries. |
| 1.9 | **CVE Lookup Agent** | "Create CVE Lookup Agent: extract signatures from feature vectors, query PostgreSQL (full-text + pgvector), score relevance" | `agentic/agents/cve_lookup.py`. Signature extraction logic (port→service, conn_state→attack_type, ssl_version→vuln, dns_query→tunneling). SQL query builder. CVSS-weighted relevance scoring. Emits reasoning events. |
| 1.10 | **Asset Discovery Agent** | "Create Asset Discovery Agent: resolve IPs to assets, enrich with services/network zones, calculate blast radius" | `agentic/agents/asset_discovery.py`. PostgreSQL joins. Impact formula: `criticality × (1 + dependent_services_count) × zone_exposure_factor`. Emits reasoning events. |

### DAY 1 — Afternoon (4h): Orchestrator + Planning Agent + LLM

| # | Task | Prompt the Agent With | Details |
|---|---|---|---|
| 1.11 | **LangGraph state machine** | "Create LangGraph orchestrator graph with nodes: triage, dispatch_agents, await_results, aggregate, plan, publish_plans, await_approval, execute, handle_failure" | `agentic/orchestrator/graph.py`, `nodes.py`, `state.py`. Conditional edges for approval routing. Redis checkpointer. Full TypedDict state. |
| 1.12 | **Triage node** | "Implement triage logic: priority scoring, deduplication window, reasoning emission" | Priority = `anomaly_score × dst_asset_criticality × (1 + has_known_cve)`. Dedup: same src_ip + attack_type within 5-min Redis window. |
| 1.13 | **Dispatch + Await nodes** | "Implement parallel agent dispatch with asyncio.gather, 30s timeout, proceed with partial results" | Dispatches CVE + Asset agents concurrently. Timeout → proceeds with whatever returned. Emits `AGENT_TIMEOUT` reasoning event. |
| 1.14 | **Context builder** | "Create context builder that assembles ThreatBundle into a structured Jinja2 prompt" | `agentic/planning/context_builder.py`. Sections: SYSTEM, ALERT_CONTEXT, CVE_CONTEXT, ASSET_CONTEXT, HISTORICAL_CONTEXT, INSTRUCTIONS. Pulls last 5 similar incidents from DB. |
| 1.15 | **LLM client** | "Create OpenAI-compatible LLM client that works with Ollama, uses Instructor for structured JSON output enforcing ExecutionPlan schema" | `agentic/planning/llm_client.py`, `structured_output.py`. Temperature=0.7 for diversity. System prompt sets role as incident responder. |
| 1.16 | **Multi-plan generation** | "Generate 3 plans (conservative, moderate, aggressive) with distinct action sets per threat type" | LLM called with instruction to produce 3 plans. Each plan has different action aggressiveness. Parsed into `PlanSet`. |
| 1.17 | **Plan ranker** | "Implement confidence scoring and risk assessment for execution plans" | `agentic/planning/plan_ranker.py`. Confidence = `(model_confidence × 0.4) + (cve_match × 0.3) + (asset_crit × 0.3)`. Risk = action destructiveness weighted by reversibility. Maps to automation tier. |
| 1.18 | **Prompt templates** | "Create Jinja2 prompt templates for threat response and re-planning after failure" | `agentic/planning/prompts/threat_response.jinja2`, `replan.jinja2`. Include few-shot examples of good plans. |
| 1.19 | **Reasoning emitter** | "Create reasoning event emitter that publishes to Redis Stream and allows WebSocket consumption" | `agentic/reasoning/emitter.py`, `events.py`, `trace.py`. Every agent node emits structured events. Trace retrieval by alert_id. |
| 1.20 | **Orchestrator main.py** | "Create main entry point that starts Kafka consumer, instantiates LangGraph, processes alerts in async loop" | `agentic/main.py`. Graceful shutdown. Health check endpoint. Configurable via env vars. |

### DAY 2 — Morning (4h): Execution Layer + Dashboard Backend

| # | Task | Prompt the Agent With | Details |
|---|---|---|---|
| 2.1 | **Action router** | "Create action router that consumes approved-actions from Kafka and dispatches to executor classes" | `execution/router.py`, `main.py`. Maps `action.type` → executor. Sequential for dependent actions, parallel for independent. |
| 2.2 | **Firewall executor** | "Create firewall executor with iptables implementation, block/unblock interface" | `execution/executors/firewall.py`. Interface: `block(ip, direction, duration)`. Subprocess wrapper for iptables. Dry-run mode for testing. |
| 2.3 | **Network isolator** | "Create network isolator executor that locks down a host via host-based firewall" | `execution/executors/isolator.py`. Interface: `isolate(hostname, zone)`. Uses SSH + iptables on target or API call to SDN controller. |
| 2.4 | **Patch executor** | "Create patch executor that triggers Ansible playbooks" | `execution/executors/patcher.py`. Interface: `patch(hostname, cve, service)`. Uses `ansible-runner` library. Playbook path configurable. |
| 2.5 | **Notifier executor** | "Create notification executor supporting Slack webhook, PagerDuty, and SMTP" | `execution/executors/notifier.py`. Interface: `notify(channel, severity, message)`. Factory pattern per channel type. |
| 2.6 | **Result reporter** | "Publish ActionResult to action-results Kafka topic after each executor" | `execution/kafka/producer.py`. Success/failure with error detail, duration, rollback info. |
| 2.7 | **Feedback consumer** | "In orchestrator, consume action-results and trigger re-planning on partial failure" | Wire into LangGraph `handle_failure` node. Emits reasoning event explaining what failed and why re-planning. |
| 2.8 | **Dashboard API** | "Extend FastAPI dashboard with REST endpoints for alerts, traces, plans, approval, and rejection" | `dashboard/api/alerts.py`, `plans.py`, `traces.py`, `actions.py`. Full CRUD. WebSocket channel for real-time push. Auth middleware (API key or JWT). |
| 2.9 | **WebSocket channels** | "Add WebSocket channels for alert notifications, plan delivery, execution status, and reasoning events" | Extend existing `server.py`. Multiple message types on single WS connection. Client subscribes to alert_id for trace updates. |

### DAY 2 — Afternoon (4h): Dashboard Frontend + Integration Test

| # | Task | Prompt the Agent With | Details |
|---|---|---|---|
| 2.10 | **React app scaffold** | "Create React + Vite + TailwindCSS + shadcn/ui frontend in dashboard/frontend/" | `package.json`, `vite.config.ts`, `tailwind.config.js`. Proxy API to FastAPI backend. |
| 2.11 | **Alert list view** | "Create AlertList component with real-time WebSocket updates, priority badges, timestamp" | `AlertList.tsx`. Colour-coded severity. Click to expand. Auto-sorts by priority. |
| 2.12 | **Reasoning trace viewer** | "Create ReasoningTrace component: expandable timeline showing every agent step with rationale, inputs, outputs, and duration" | `ReasoningTrace.tsx`. Collapsible nodes. LLM prompt/response viewable on click. Shows confidence at each step. Timestamps + durations. Visual distinction per agent (colour-coded). |
| 2.13 | **Plan approval cards** | "Create PlanCard component with confidence badge, risk level, action list with rationale, approve/modify/reject buttons" | `PlanCard.tsx`. Modification mode allows editing action params inline. Confirmation dialog. Shows automation tier recommendation. |
| 2.14 | **LLM prompt viewer** | "Create LLMPromptViewer component that shows full prompt text and raw model response in expandable sections" | `LLMPromptViewer.tsx`. Syntax-highlighted. Copy button. Shows token count. Side-by-side prompt/response view. |
| 2.15 | **Execution status** | "Create ExecutionStatus component showing live progress of approved actions" | `ExecutionStatus.tsx`. Progress bars per action. Success/failure icons. Duration. Link back to reasoning trace. |
| 2.16 | **End-to-end integration test** | "Create integration test: inject synthetic alert → verify full pipeline → verify reasoning trace completeness" | `agentic/tests/test_e2e.py`. Uses `docker compose` test profile. Synthetic alert → CVE match → asset → LLM plan → approval simulation → execution mock → trace verification. |
| 2.17 | **Failure scenario tests** | "Create tests for: CVE DB down, Redis down, LLM timeout, executor failure, approval timeout" | Tests that each failure path emits correct reasoning events and triggers appropriate fallback behaviour. |
| 2.18 | **Docker compose full stack** | "Update docker-compose.yml with all new services: orchestrator, execution-layer, updated dashboard" | Final integration. All services start cleanly. Correct dependency ordering. |

### Implementation Order (Critical Path)

```
docker-compose (infra) → DB migrations → seed data → Pydantic models
    → Kafka client → Redis client → Base agent
    → CVE agent + Asset agent (parallel)
    → LangGraph orchestrator → Planning agent → LLM client
    → Reasoning emitter (wired into all nodes)
    → Execution layer
    → Dashboard API → Frontend
    → Integration test
```

### What to Skip for Day 1–2 (Defer to Day 3+)

| Deferred | Reason |
|---|---|
| Fine-tuning (Unsloth + training data curation) | Use Mistral-7B-Instruct out-of-box via Ollama. Fine-tune later with production data. |
| pgvector semantic search | Full-text search is sufficient for MVP. Add embeddings when you have more CVE correlation data. |
| Load testing (100 alerts burst) | Functional correctness first. Performance tuning after. |
| RBAC / JWT auth on dashboard | Add after core flow works. Use API key for now. |
| Ansible playbook library | Mock the patch executor. Wire real playbooks when you have target infrastructure. |

---

## 4. Directory Structure

```
Sentinel/
├── capture/                              ← existing (Layer 1a)
│   ├── pcap/
│   ├── zeek/
│   └── generate_sample.py
│
├── ingestion/                            ← existing (Layer 1b)
│   ├── Dockerfile
│   ├── main.py
│   ├── requirements.txt
│   ├── features/extractor.py
│   ├── kafka/producer.py
│   ├── pipeline/watcher.py
│   └── zeek/
│       ├── Dockerfile
│       └── entrypoint.sh
│
├── hybrid-detection/                     ← Layer 2
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                           ← entry: consume network-features, produce anomaly-alerts
│   ├── models/
│   │   ├── autoencoder.py                ← unsupervised anomaly scorer
│   │   └── random_forest.py             ← supervised classifier
│   ├── ensemble.py                       ← voting / stacking combiner
│   ├── kafka/
│   │   ├── consumer.py                   ← consume network-features
│   │   └── producer.py                   ← produce anomaly-alerts
│   └── tests/
│       └── test_ensemble.py
│
├── agentic/                              ← Layer 3 (this implementation)
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                           ← entry: starts orchestrator + agent workers
│   │
│   ├── orchestrator/
│   │   ├── __init__.py
│   │   ├── graph.py                      ← LangGraph state machine definition
│   │   ├── nodes.py                      ← graph node functions (triage, dispatch, aggregate, plan)
│   │   ├── state.py                      ← TypedDict for graph state
│   │   └── config.py                     ← thresholds, timeouts, feature flags
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base.py                       ← BaseAgent abstract class (execute, emit_reasoning, retry)
│   │   ├── cve_lookup.py                 ← CVE signature extraction + DB query + scoring
│   │   ├── asset_discovery.py            ← IP resolution + enrichment + impact assessment
│   │   └── registry.py                   ← agent registry (name → class mapping)
│   │
│   ├── planning/
│   │   ├── __init__.py
│   │   ├── context_builder.py            ← assemble ThreatBundle → LLM prompt
│   │   ├── llm_client.py                 ← OpenAI-compatible client (vLLM/Ollama)
│   │   ├── plan_ranker.py               ← confidence scoring + risk assessment + ranking
│   │   ├── structured_output.py          ← Instructor/Outlines schema enforcement
│   │   └── prompts/
│   │       ├── threat_response.jinja2    ← main planning prompt template
│   │       └── replan.jinja2             ← re-planning after execution failure
│   │
│   ├── reasoning/
│   │   ├── __init__.py
│   │   ├── events.py                     ← ReasoningEvent model + event types enum
│   │   ├── emitter.py                    ← emit reasoning events to Redis Stream
│   │   └── trace.py                      ← build full trace from event stream (for API)
│   │
│   ├── state/
│   │   ├── __init__.py
│   │   ├── redis_client.py               ← connection pool, helpers
│   │   ├── task_queue.py                 ← Redis Streams-based agent task queue
│   │   ├── result_store.py              ← per-incident result cache (Hash + TTL)
│   │   └── session.py                    ← incident session state management
│   │
│   ├── kafka/
│   │   ├── __init__.py
│   │   ├── consumer.py                   ← anomaly-alerts consumer + action-results consumer
│   │   └── producer.py                   ← execution-plans producer
│   │
│   ├── db/
│   │   ├── __init__.py
│   │   ├── connection.py                 ← asyncpg connection pool
│   │   ├── cve_repository.py            ← CVE queries (full-text + optional vector search)
│   │   ├── asset_repository.py          ← asset/service/network zone queries
│   │   └── incident_repository.py       ← incident history read/write
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── alert.py                      ← AnomalyAlert pydantic model
│   │   ├── cve.py                        ← CVEMatch, CVEEntry models
│   │   ├── asset.py                      ← AssetInfo, ServiceInfo, NetworkZone models
│   │   ├── plan.py                       ← ExecutionPlan, Action, PlanSet models
│   │   ├── reasoning.py                  ← ReasoningEvent, ReasoningTrace models
│   │   └── threat_bundle.py             ← ThreatBundle (aggregated context for LLM)
│   │
│   └── tests/
│       ├── conftest.py                   ← fixtures (mock DB, mock Redis, mock Kafka)
│       ├── test_cve_lookup.py
│       ├── test_asset_discovery.py
│       ├── test_orchestrator_graph.py
│       ├── test_plan_ranker.py
│       └── test_reasoning_trace.py
│
├── execution/                            ← Layer 4
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                           ← entry: consume approved-actions, dispatch executors
│   │
│   ├── router.py                         ← action_type → executor class mapping
│   │
│   ├── executors/
│   │   ├── __init__.py
│   │   ├── base.py                       ← BaseExecutor abstract (execute, rollback, report)
│   │   ├── firewall.py                   ← iptables / cloud SG / pfSense
│   │   ├── isolator.py                   ← VLAN reassign / SDN / host firewall
│   │   ├── patcher.py                    ← Ansible Runner integration
│   │   ├── notifier.py                   ← Slack / PagerDuty / SMTP
│   │   └── threat_hunter.py             ← trigger deep PCAP re-analysis
│   │
│   ├── kafka/
│   │   ├── consumer.py                   ← approved-actions consumer
│   │   └── producer.py                   ← action-results producer
│   │
│   └── tests/
│       ├── test_router.py
│       └── test_executors.py
│
├── dashboard/                            ← Extended (Layer 5 – Human Interface)
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── server.py                         ← existing + new REST endpoints + WebSocket channels
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── alerts.py                     ← GET /alerts, GET /alerts/{id}
│   │   ├── plans.py                      ← GET /alerts/{id}/plans, POST approve/reject
│   │   ├── traces.py                     ← GET /alerts/{id}/trace (reasoning chain)
│   │   └── actions.py                    ← GET /alerts/{id}/actions (execution status)
│   │
│   ├── frontend/                         ← React app (new)
│   │   ├── package.json
│   │   ├── tailwind.config.js
│   │   ├── src/
│   │   │   ├── App.tsx
│   │   │   ├── main.tsx
│   │   │   ├── components/
│   │   │   │   ├── AlertList.tsx         ← live alert feed
│   │   │   │   ├── AlertDetail.tsx       ← single alert deep dive
│   │   │   │   ├── ReasoningTrace.tsx    ← expandable timeline of agent steps
│   │   │   │   ├── PlanCard.tsx          ← plan with actions + approve/reject buttons
│   │   │   │   ├── ExecutionStatus.tsx   ← live action progress
│   │   │   │   └── LLMPromptViewer.tsx   ← expandable prompt/response viewer
│   │   │   ├── hooks/
│   │   │   │   ├── useWebSocket.ts       ← real-time alert/plan push
│   │   │   │   └── useTrace.ts           ← fetch reasoning trace for alert
│   │   │   └── lib/
│   │   │       └── api.ts                ← REST client
│   │   └── index.html
│   │
│   └── index.html                        ← existing (Layer 1 dashboard, kept as-is)
│
├── database/                             ← Database schemas & migrations
│   ├── migrations/
│   │   ├── 001_create_cve_entries.sql
│   │   ├── 002_create_assets.sql
│   │   ├── 003_create_incidents.sql
│   │   └── 004_create_reasoning_traces.sql
│   ├── seed/
│   │   ├── seed_cves.py                  ← NVD sync script
│   │   └── seed_assets.py               ← sample asset inventory
│   └── schema.sql                        ← full DDL for reference
│
├── scripts/
│   ├── sync_nvd.py                       ← cron job: pull CVEs from NVD API → PostgreSQL
│   └── fine_tune.py                      ← Unsloth fine-tuning script for planning LLM
│
├── docs/
│   └── architecture/
│       ├── AGENTIC_LAYER.md              ← architecture diagrams
│       ├── IMPLEMENTATION_GUIDE.md       ← this document
│       └── diagrams.html                 ← rendered Mermaid viewer
│
├── docker-compose.yml                    ← extended with all services
├── .env.example                          ← environment variable template
└── README.md
```

---

## 5. Reasoning Trace – Technical Implementation

### Event Model

```python
class ReasoningEventType(str, Enum):
    ALERT_RECEIVED = "alert_received"
    TRIAGE_DECISION = "triage_decision"
    AGENT_DISPATCHED = "agent_dispatched"
    AGENT_RESULT = "agent_result"
    AGENT_TIMEOUT = "agent_timeout"
    CONTEXT_BUILT = "context_built"
    LLM_PROMPT = "llm_prompt"
    LLM_RESPONSE = "llm_response"
    PLAN_SCORED = "plan_scored"
    PLAN_PUBLISHED = "plan_published"
    APPROVAL_RECEIVED = "approval_received"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_RESULT = "execution_result"

class ReasoningEvent(BaseModel):
    event_id: str
    alert_id: str
    timestamp: datetime
    event_type: ReasoningEventType
    agent: str                          # which agent emitted this
    action: str                         # what it did
    input_summary: str                  # condensed input (for display)
    output_summary: str                 # condensed output (for display)
    full_input: dict | None = None      # expandable detail (e.g., full LLM prompt)
    full_output: dict | None = None     # expandable detail (e.g., full LLM response)
    rationale: str                      # WHY this decision was made
    duration_ms: int                    # how long this step took
    confidence: float | None = None     # if applicable
```

### Flow

```
Agent step executes
    → emitter.emit(ReasoningEvent) 
    → Redis Stream: "reasoning:{alert_id}"
    → WebSocket push to connected dashboard clients
    → Also persisted to PostgreSQL reasoning_traces table (async)

Dashboard requests full trace:
    GET /alerts/{alert_id}/trace
    → Read Redis Stream "reasoning:{alert_id}"
    → Return ordered list of ReasoningEvents
    → Frontend renders as interactive timeline
```

### What Each Agent Emits

| Agent | Events Emitted | Rationale Content |
|---|---|---|
| **Orchestrator (triage)** | `TRIAGE_DECISION` | "Priority HIGH because anomaly_score=0.91 AND dst_ip maps to criticality-2 asset" |
| **CVE Lookup** | `AGENT_DISPATCHED`, `AGENT_RESULT` | "Searched NVD for 'openssh port:22 conn_state:S0'. Found 3 CVEs. Top match CVE-2024-XXXX (cvss=8.1) because dst_port=22 + active exploit in wild" |
| **Asset Discovery** | `AGENT_DISPATCHED`, `AGENT_RESULT` | "Resolved 10.0.0.1 → web-prod-01. Criticality=2 (production web server). Zone=DMZ. Blast radius: 3 downstream services depend on this host" |
| **Planning (context)** | `CONTEXT_BUILT` | "Assembled context: 1 alert + 2 CVE matches + 1 asset + 3 historical incidents with similar pattern" |
| **Planning (LLM)** | `LLM_PROMPT`, `LLM_RESPONSE` | Full prompt text in `full_input`. Raw model output in `full_output`. Summary: "Generated 3 plans with aggression levels: conservative, moderate, aggressive" |
| **Planning (ranker)** | `PLAN_SCORED` | "Plan A confidence=0.87: (model=0.85 × 0.4) + (cve_match=0.92 × 0.3) + (asset_crit=0.85 × 0.3). Risk=MEDIUM because firewall_block is reversible" |

---

## 6. LangGraph Orchestrator Definition (Conceptual)

```python
from langgraph.graph import StateGraph, END

# State shared across all nodes
class OrchestratorState(TypedDict):
    alert: AnomalyAlert
    priority: str
    cve_results: list[CVEMatch] | None
    asset_results: list[AssetInfo] | None
    threat_bundle: ThreatBundle | None
    plans: PlanSet | None
    approval: ApprovalDecision | None
    execution_results: list[ActionResult] | None
    reasoning_events: list[ReasoningEvent]

# Build graph
graph = StateGraph(OrchestratorState)

graph.add_node("triage", triage_node)
graph.add_node("dispatch_agents", dispatch_node)
graph.add_node("await_results", await_results_node)
graph.add_node("aggregate", aggregate_node)
graph.add_node("plan", planning_node)
graph.add_node("publish_plans", publish_node)
graph.add_node("await_approval", await_approval_node)
graph.add_node("execute", execute_node)
graph.add_node("handle_failure", failure_node)

# Edges
graph.set_entry_point("triage")
graph.add_edge("triage", "dispatch_agents")
graph.add_edge("dispatch_agents", "await_results")
graph.add_edge("await_results", "aggregate")
graph.add_edge("aggregate", "plan")
graph.add_edge("plan", "publish_plans")
graph.add_edge("publish_plans", "await_approval")

# Conditional edges
graph.add_conditional_edges("await_approval", route_approval, {
    "approved": "execute",
    "rejected": END,
    "timeout": END,  # escalated
})
graph.add_conditional_edges("execute", route_execution, {
    "success": END,
    "partial_failure": "handle_failure",
})
graph.add_edge("handle_failure", "plan")  # re-plan with failure context

orchestrator = graph.compile(checkpointer=RedisCheckpointer())
```

---

## 7. Key Dependencies (requirements.txt)

```
# agentic/requirements.txt
langgraph>=0.2.0
langchain-core>=0.3.0
langfuse>=2.0.0              # reasoning trace observability
instructor>=1.0.0            # structured LLM output
openai>=1.0.0                # OpenAI-compatible client (for vLLM/Ollama)
confluent-kafka>=2.3.0       # Kafka producer/consumer
redis>=5.0.0                 # Redis Streams + pub/sub
asyncpg>=0.29.0              # async PostgreSQL
pydantic>=2.5.0              # data models
jinja2>=3.1.0                # prompt templates
structlog>=24.1.0            # structured logging
httpx>=0.27.0                # async HTTP (for NVD API)
pytest>=8.0.0                # testing
pytest-asyncio>=0.23.0       # async test support
```

---

## 8. Docker Compose Additions

```yaml
# New services to add to docker-compose.yml:

  postgres:
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_DB: sentinel
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./database/migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sentinel"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redisdata:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  vllm:
    image: vllm/vllm-openai:latest
    runtime: nvidia    # requires nvidia-docker
    environment:
      MODEL: ./models/sentinel-mistral-7b
    volumes:
      - ./models:/models
    ports:
      - "8000:8000"
    deploy:
      resources:
        reservations:
          devices:
            - capabilities: [gpu]

  langfuse:
    image: langfuse/langfuse:2
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://sentinel:${POSTGRES_PASSWORD}@postgres:5432/sentinel
      NEXTAUTH_SECRET: ${LANGFUSE_SECRET}
      NEXTAUTH_URL: http://localhost:3000
    ports:
      - "3000:3000"

  orchestrator:
    build:
      context: ./agentic
      dockerfile: Dockerfile
    depends_on:
      kafka: { condition: service_healthy }
      redis: { condition: service_healthy }
      postgres: { condition: service_healthy }
    environment:
      KAFKA_BOOTSTRAP_SERVERS: kafka:9092
      REDIS_URL: redis://redis:6379
      DATABASE_URL: postgresql://sentinel:${POSTGRES_PASSWORD}@postgres:5432/sentinel
      LLM_BASE_URL: http://vllm:8000/v1
      LLM_MODEL: sentinel-mistral-7b
      LANGFUSE_HOST: http://langfuse:3000
      LANGFUSE_PUBLIC_KEY: ${LANGFUSE_PUBLIC_KEY}
      LANGFUSE_SECRET_KEY: ${LANGFUSE_SECRET_KEY}

  execution-layer:
    build:
      context: ./execution
      dockerfile: Dockerfile
    depends_on:
      kafka: { condition: service_healthy }
      redis: { condition: service_healthy }
    environment:
      KAFKA_BOOTSTRAP_SERVERS: kafka:9092
      REDIS_URL: redis://redis:6379
```
