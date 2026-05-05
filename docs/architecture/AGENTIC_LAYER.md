# Sentinel – Agentic Layer Architecture (Layer 3)

> Multi-agent orchestration for automated threat analysis, CVE correlation, and human-in-the-loop response planning.

---

## 1. System-Wide Architecture (All Layers)

Shows how the agentic layer (Layer 3) fits between the hybrid detection layer (Layer 2) and the execution layer (Layer 4), with Kafka as the backbone messaging system.

```mermaid
flowchart TB
    subgraph L1["LAYER 1 – INGESTION (existing)"]
        PCAP["PCAP Files"]
        ZEEK["Zeek Engine"]
        FE["Feature Extractor"]
        PCAP --> ZEEK --> FE
    end

    subgraph KAFKA["KAFKA MESSAGE BUS"]
        T1[/"network-features"/]
        T2[/"anomaly-alerts"/]
        T4[/"execution-plans"/]
        T5[/"approved-actions"/]
        T6[/"action-results"/]
    end

    subgraph L2["LAYER 2 – HYBRID DETECTION"]
        AE["Autoencoder\n(Unsupervised)"]
        RF["Random Forest\n(Supervised)"]
        ENS["Ensemble Classifier"]
        AE --> ENS
        RF --> ENS
    end

    subgraph L3["LAYER 3 – AGENTIC"]
        ORCH["Orchestrator Agent"]
        CVE_A["CVE Lookup Agent"]
        ASSET_A["Asset Discovery Agent"]
        PLAN_A["Planning Agent\n(Fine-tuned LLM)"]
    end

    subgraph L4["LAYER 4 – EXECUTION"]
        FW["Firewall Controller"]
        ISO["Network Isolator"]
        PATCH["Patch Manager"]
        NOTIFY["Alert Broadcaster"]
    end

    subgraph HUMAN["HUMAN-IN-THE-LOOP"]
        SOC["SOC Analyst Dashboard"]
    end

    subgraph DATA["DATA STORES"]
        CVE_DB[("CVE / NVD\nDatabase")]
        ASSET_DB[("Asset\nInventory")]
        INCIDENT_DB[("Incident\nHistory")]
        REDIS[("Redis\nAgent State")]
    end

    FE -->|publish| T1
    T1 -->|consume| ENS
    ENS -->|"anomaly detected\n(label + score + features)"| T2
    T2 -->|consume| ORCH
    ORCH -->|dispatch| CVE_A
    ORCH -->|dispatch| ASSET_A
    CVE_A -->|query| CVE_DB
    ASSET_A -->|query| ASSET_DB
    CVE_A -.->|results| ORCH
    ASSET_A -.->|results| ORCH
    ORCH -->|"enriched context"| PLAN_A
    PLAN_A -->|"ranked plans\n+ confidence"| T4
    T4 -->|"notify + plan list"| SOC
    SOC -->|"approve / reject / modify"| T5
    T5 -->|execute| FW
    T5 -->|execute| ISO
    T5 -->|execute| PATCH
    T5 -->|execute| NOTIFY
    FW & ISO & PATCH & NOTIFY -->|result| T6
    T6 -->|feedback| ORCH
    ORCH -->|log| INCIDENT_DB
    ORCH <-.->|state| REDIS
```

---

## 2. Agentic Layer – Internal Architecture

Zooms into the orchestrator and its sub-agents, showing the internal message flow, state management, and how the fine-tuned LLM is invoked.

```mermaid
flowchart TD
    subgraph INPUT["INBOUND (from Layer 2)"]
        KA_IN[/"Kafka: anomaly-alerts"/]
    end

    subgraph ORCHESTRATOR["ORCHESTRATOR AGENT"]
        direction TB
        RECV["Alert Receiver"]
        TRIAGE["Triage & Prioritisation"]
        DISPATCH["Agent Dispatcher"]
        AGG["Result Aggregator"]
        RECV --> TRIAGE --> DISPATCH
        DISPATCH --> AGG
    end

    subgraph SUB_AGENTS["SUB-AGENTS (parallel dispatch)"]
        direction TB
        CVE["CVE Lookup Agent"]
        ASSET["Asset Discovery Agent"]
    end

    subgraph PLANNING["PLANNING AGENT"]
        direction TB
        CTX["Context Builder"]
        LLM["Fine-tuned LLM\n(threat response)"]
        RANK["Plan Ranker\n& Confidence Scorer"]
        CTX --> LLM --> RANK
    end

    subgraph STATE["SHARED STATE (Redis)"]
        AGENT_Q["Agent Task Queue"]
        RESULT_STORE["Result Store"]
        SESSION["Session State"]
    end

    subgraph OUTPUT["OUTBOUND"]
        KA_PLAN[/"Kafka: execution-plans"/]
        WS_NOTIFY["WebSocket → SOC Dashboard"]
    end

    KA_IN -->|"anomaly alert JSON"| RECV

    DISPATCH -->|"lookup task"| CVE
    DISPATCH -->|"lookup task"| ASSET

    CVE -.->|"CVE matches"| AGG
    ASSET -.->|"affected assets"| AGG

    AGG -->|"enriched threat bundle"| CTX

    RANK -->|"plan list + scores"| KA_PLAN
    RANK -->|"push notification"| WS_NOTIFY

    DISPATCH <-.-> AGENT_Q
    CVE & ASSET <-.-> RESULT_STORE
    RECV & AGG <-.-> SESSION
```

---

## 3. Kafka Topic Schema & Message Flow

Defines every Kafka topic the agentic layer touches, including message direction and payload purpose.

```mermaid
flowchart LR
    subgraph TOPICS["KAFKA TOPICS"]
        direction TB
        T1[/"network-features\n(Layer 1 → Layer 2)"/]
        T2[/"anomaly-alerts\n(Layer 2 → Layer 3)"/]
        T4[/"execution-plans\n(Layer 3 → Dashboard)"/]
        T5[/"approved-actions\n(Dashboard → Layer 4)"/]
        T6[/"action-results\n(Layer 4 → Layer 3)"/]
    end

    L1["Layer 1\nIngestion"] -->|"feature vectors"| T1
    L2["Layer 2\nDetection"] -->|consume| T1
    L2 -->|"alert + classification\n+ raw features"| T2
    L3["Layer 3\nAgentic"] -->|consume| T2
    L3 -->|"plan list + confidence\n+ threat context"| T4
    DASH["SOC Dashboard"] -->|consume| T4
    DASH -->|"selected plan ID\n+ analyst notes"| T5
    L4["Layer 4\nExecution"] -->|consume| T5
    L4 -->|"action status\n+ result payload"| T6
    L3 -->|consume| T6
```

### Topic Payload Summaries

| Topic | Producer | Consumer | Key Fields |
|---|---|---|---|
| `network-features` | Feature Extractor | Hybrid Detection | `uid`, `src_ip`, `dst_ip`, `proto`, `duration`, `bytes_ratio`, `conn_state_*`, `ssl_*`, `dns_*` |
| `anomaly-alerts` | Hybrid Detection | Orchestrator Agent | `alert_id`, `timestamp`, `anomaly_score`, `classification`, `feature_vector`, `model_votes` |
| `execution-plans` | Planning Agent | SOC Dashboard | `alert_id`, `threat_summary`, `cve_matches[]`, `affected_assets[]`, `plans[]` (each with `plan_id`, `actions[]`, `confidence`, `risk_level`) |
| `approved-actions` | SOC Dashboard | Execution Layer | `plan_id`, `alert_id`, `approved_by`, `actions[]`, `modifications`, `approval_timestamp` |
| `action-results` | Execution Layer | Orchestrator Agent | `plan_id`, `action_id`, `status`, `result_payload`, `error`, `completed_at` |

---

## 4. CVE Lookup Agent – Detail

Shows how the CVE Lookup Agent maps traffic characteristics to known exploits.

```mermaid
flowchart TD
    subgraph INPUT["FROM ORCHESTRATOR"]
        TASK["Lookup Task\n(feature vector + classification)"]
    end

    subgraph CVE_AGENT["CVE LOOKUP AGENT"]
        EXTRACT["Extract Signatures"]
        QUERY["Query Builder"]
        SEARCH["CVE Database Search"]
        SCORE["Relevance Scorer"]
        EXTRACT --> QUERY --> SEARCH --> SCORE
    end

    subgraph SIGNATURE_EXTRACTION["SIGNATURE EXTRACTION LOGIC"]
        direction TB
        S1["dst_port → target service"]
        S2["proto + conn_state → attack pattern"]
        S3["bytes_ratio / pkts_ratio → exfil heuristic"]
        S4["ssl_version + cipher → TLS vuln"]
        S5["dns_query + dns_answers → DNS-based attack"]
    end

    subgraph CVE_SOURCES["CVE DATA SOURCES"]
        NVD[("NIST NVD API\n(nvd.nist.gov)")]
        LOCAL[("Local CVE Mirror\n(PostgreSQL)")]
        MITRE[("MITRE ATT&CK\nMapping")]
    end

    subgraph OUTPUT["TO ORCHESTRATOR"]
        RESULTS["CVE Match Results\n(cve_id, cvss, description,\nmatched_signature, confidence)"]
    end

    TASK --> EXTRACT
    EXTRACT --> SIGNATURE_EXTRACTION
    SIGNATURE_EXTRACTION --> QUERY
    QUERY --> NVD & LOCAL & MITRE
    NVD & LOCAL & MITRE --> SEARCH
    SCORE --> RESULTS
```

### Signature-to-CVE Mapping Logic

| Traffic Pattern | Extracted Signature | CVE Search Strategy |
|---|---|---|
| Port scan (many `conn_state_S0` to sequential ports) | `attack_type: port_scan`, target port range | Match CVEs for services on targeted ports |
| High `bytes_ratio` outbound, long duration | `attack_type: data_exfiltration`, volume estimate | Match C2/exfil CVEs for the destination service |
| Deprecated `ssl_version` (SSLv3, TLSv1.0) | `vuln_type: weak_tls`, specific version string | Direct CVE lookup (e.g., CVE-2014-3566 POODLE) |
| Unusual `dns_query` patterns (DGA-like) | `attack_type: dns_tunneling`, query entropy | Match DNS tunneling / DGA CVEs |
| Anomalous `resp_bytes` with `conn_state_RSTO` | `attack_type: exploit_attempt`, service + port | Match RCE/DoS CVEs for the target service |

---

## 5. Asset Discovery Agent – Detail

```mermaid
flowchart TD
    subgraph INPUT["FROM ORCHESTRATOR"]
        TASK["Lookup Task\n(src_ip, dst_ip, dst_port, service)"]
    end

    subgraph ASSET_AGENT["ASSET DISCOVERY AGENT"]
        RESOLVE["IP → Asset Resolver"]
        ENRICH["Asset Enrichment"]
        IMPACT["Impact Assessor"]
        RESOLVE --> ENRICH --> IMPACT
    end

    subgraph ASSET_DB["ASSET INVENTORY (PostgreSQL)"]
        HOSTS[("Hosts\nhostname, os, owner,\ncriticality_tier")]
        SERVICES_DB[("Services\nport, software, version")]
        NETWORK[("Network Zones\nVLAN, subnet, trust_level")]
    end

    subgraph OUTPUT["TO ORCHESTRATOR"]
        RESULTS["Affected Assets\n(hostname, criticality, services,\nnetwork_zone, blast_radius)"]
    end

    TASK --> RESOLVE
    RESOLVE --> HOSTS & SERVICES_DB & NETWORK
    HOSTS & SERVICES_DB & NETWORK --> ENRICH
    IMPACT --> RESULTS
```

### Asset Enrichment Fields

| Field | Source | Purpose |
|---|---|---|
| `hostname` | IP → Host reverse lookup | Human-readable identification |
| `os` / `os_version` | Asset inventory | Determines CVE applicability |
| `owner` / `department` | Asset inventory | Notification routing |
| `criticality_tier` | Asset inventory (1-5) | Prioritises response urgency |
| `running_services` | Service catalog | Matches CVE to specific software versions |
| `network_zone` | Network topology DB | Calculates blast radius and lateral movement risk |
| `last_vuln_scan` | Vuln scanner integration | Determines if asset is already known-vulnerable |

---

## 6. Planning Agent & LLM Interaction

```mermaid
flowchart TD
    subgraph INPUT["FROM ORCHESTRATOR (aggregated)"]
        BUNDLE["Enriched Threat Bundle"]
    end

    subgraph CTX_BUILD["CONTEXT BUILDER"]
        ALERT_CTX["Alert Context\n(score, classification,\nraw features)"]
        CVE_CTX["CVE Context\n(matched CVEs, CVSS,\nexploit availability)"]
        ASSET_CTX["Asset Context\n(affected hosts,\ncriticality, blast radius)"]
        HIST_CTX["Historical Context\n(similar past incidents,\nactions taken)"]
    end

    subgraph LLM_CALL["FINE-TUNED LLM (threat response)"]
        PROMPT["Structured Prompt\n(system + context + instruction)"]
        GENERATE["LLM Generation\n(multiple candidate plans)"]
        PARSE["Response Parser\n(structured JSON extraction)"]
        PROMPT --> GENERATE --> PARSE
    end

    subgraph RANKING["PLAN RANKER & CONFIDENCE SCORER"]
        CONF["Confidence Scoring"]
        RISK["Risk Assessment"]
        RANK["Plan Ranking"]
        CONF --> RANK
        RISK --> RANK
    end

    subgraph OUTPUT["OUTBOUND"]
        PLANS["Ranked Execution Plans\n→ Kafka: execution-plans\n→ WebSocket: SOC Dashboard"]
    end

    BUNDLE --> ALERT_CTX & CVE_CTX & ASSET_CTX & HIST_CTX
    ALERT_CTX & CVE_CTX & ASSET_CTX & HIST_CTX --> PROMPT
    PARSE --> CONF & RISK
    RANK --> PLANS
```

### Confidence Thresholds & Automation Tiers

| Confidence | Risk Level | Automation Tier | Human Action Required |
|---|---|---|---|
| ≥ 0.95 | Low | **Auto-execute** | Notification only (post-action) |
| 0.80 – 0.94 | Low–Medium | **Auto-recommend** | One-click approval with 15-min timeout |
| 0.60 – 0.79 | Medium | **Suggest** | Analyst must review and explicitly approve |
| 0.40 – 0.59 | Medium–High | **Advise** | Analyst review + supervisor sign-off |
| < 0.40 | High | **Escalate** | Full manual investigation required |

### Execution Plan Structure (per plan)

```json
{
  "plan_id": "plan-a1b2c3",
  "alert_id": "alert-x9y8z7",
  "confidence": 0.87,
  "risk_level": "medium",
  "automation_tier": "auto-recommend",
  "threat_summary": "Port scan from 172.16.0.55 targeting 25 ports on 10.0.0.1, matching CVE-2024-XXXX (OpenSSH pre-auth)",
  "actions": [
    {
      "action_id": "act-001",
      "type": "firewall_block",
      "target": "172.16.0.55",
      "params": {"direction": "inbound", "duration_hours": 24},
      "rationale": "Block scanning source IP at perimeter"
    },
    {
      "action_id": "act-002",
      "type": "patch",
      "target": "10.0.0.1",
      "params": {"cve": "CVE-2024-XXXX", "service": "openssh", "version": "9.6p1"},
      "rationale": "Upgrade OpenSSH to patched version"
    },
    {
      "action_id": "act-003",
      "type": "notify",
      "target": "soc-team",
      "params": {"channel": "slack", "severity": "high"},
      "rationale": "Alert SOC team of active reconnaissance"
    }
  ],
  "alternative_plans": ["plan-d4e5f6"],
  "cve_matches": [
    {"cve_id": "CVE-2024-XXXX", "cvss": 8.1, "confidence": 0.82}
  ],
  "affected_assets": [
    {"hostname": "web-prod-01", "criticality": 2, "network_zone": "dmz"}
  ]
}
```

---

## 7. Human-in-the-Loop – Approval Flow

```mermaid
sequenceDiagram
    participant L2 as Hybrid Detection
    participant KA as Kafka
    participant ORCH as Orchestrator
    participant CVE as CVE Agent
    participant ASSET as Asset Agent
    participant LLM as Planning Agent
    participant DASH as SOC Dashboard
    participant ANALYST as SOC Analyst
    participant EXEC as Execution Layer

    L2->>KA: anomaly-alerts (score=0.91, classification=port_scan)
    KA->>ORCH: consume alert

    par Sub-agent dispatch
        ORCH->>CVE: lookup(dst_ports, proto, conn_states)
        ORCH->>ASSET: lookup(src_ip=172.16.0.55, dst_ip=10.0.0.1)
    end

    CVE-->>ORCH: CVE-2024-XXXX (cvss=8.1, openssh pre-auth)
    ASSET-->>ORCH: web-prod-01 (criticality=2, dmz, openssh 9.5)

    ORCH->>LLM: enriched threat bundle
    LLM-->>ORCH: 3 ranked plans (conf: 0.87, 0.72, 0.51)

    ORCH->>KA: execution-plans (3 plans)
    KA->>DASH: push plans to dashboard
    DASH->>ANALYST: 🔔 notification + plan cards

    alt Analyst approves Plan A (conf 0.87)
        ANALYST->>DASH: approve plan-a1b2c3
        DASH->>KA: approved-actions (plan-a1b2c3)
        KA->>EXEC: execute actions
        EXEC-->>KA: action-results (success)
        KA->>ORCH: feedback → log to incident DB
    else Analyst modifies Plan B
        ANALYST->>DASH: modify plan-d4e5f6 (extend block to 48h)
        DASH->>KA: approved-actions (modified plan)
        KA->>EXEC: execute modified actions
    else Analyst rejects all
        ANALYST->>DASH: reject all + notes
        DASH->>KA: rejection event
        KA->>ORCH: log rejection, await manual investigation
    end
```

---

## 8. Messaging Infrastructure

```mermaid
flowchart TD
    subgraph KAFKA_LAYER["KAFKA (async, durable, inter-layer)"]
        direction LR
        K1[/"network-features\n3 partitions"/]
        K2[/"anomaly-alerts\n3 partitions"/]
        K4[/"execution-plans\n1 partition (ordered)"/]
        K5[/"approved-actions\n1 partition (ordered)"/]
        K6[/"action-results\n1 partition"/]
    end

    subgraph REDIS_LAYER["REDIS (real-time, intra-agent)"]
        direction LR
        R1["Agent Task Queue\n(Redis Streams)"]
        R2["Result Store\n(Redis Hash)"]
        R3["Session State\n(Redis Hash, TTL=1h)"]
        R4["Agent Heartbeat\n(Redis pub/sub)"]
    end

    subgraph WS_LAYER["WEBSOCKET (real-time, human-facing)"]
        direction LR
        W1["Alert Notifications\n(push to browser)"]
        W2["Plan Presentation\n(push to browser)"]
        W3["Approval Commands\n(browser to server)"]
        W4["Execution Status\n(push to browser)"]
    end

    L1["Layer 1"] --> K1
    L2["Layer 2"] --> K2
    L3_ORCH["Orchestrator"] --> R1 & R2 & R3
    L3_PLAN["Planning Agent"] --> K4
    K4 --> WS_LAYER
    WS_LAYER --> K5
    K5 --> L4["Layer 4"]
    L4 --> K6
    K6 --> L3_ORCH
```

### Why Three Messaging Systems?

| System | Role | Justification |
|---|---|---|
| **Kafka** | Inter-layer, durable, async | Persistent log of all alerts, plans, and actions for audit. Handles backpressure. Decouples layers so any can restart without data loss. Partitioned for throughput on high-volume topics. |
| **Redis Streams/Pub-Sub** | Intra-agent coordination | Sub-agents need low-latency task dispatch and result collection within the agentic layer. Redis Streams provide consumer-group semantics for the task queue. Heartbeats via pub/sub detect agent failures in < 2s. Session state with TTL prevents stale context accumulation. |
| **WebSocket** | Human-facing real-time UI | SOC analysts need instant push notifications and interactive plan approval. HTTP polling would add unacceptable latency for time-critical security response. Bidirectional channel supports approval commands back from the browser. |

---

## 9. Execution Layer Interface

```mermaid
flowchart TD
    subgraph APPROVED["KAFKA: approved-actions"]
        MSG["Plan + Actions JSON"]
    end

    subgraph ROUTER["ACTION ROUTER"]
        PARSE["Parse Action Type"]
    end

    subgraph EXECUTORS["EXECUTORS"]
        FW["Firewall Controller\n(iptables / cloud SG API)"]
        ISO["Network Isolator\n(VLAN reassignment / SDN)"]
        PATCH["Patch Manager\n(Ansible / Salt playbook)"]
        ALERT["Alert Broadcaster\n(Slack / PagerDuty / Email)"]
        HUNT["Threat Hunter\n(trigger deep PCAP analysis)"]
    end

    subgraph FEEDBACK["KAFKA: action-results"]
        RES["Status + Result Payload"]
    end

    MSG --> PARSE
    PARSE -->|"firewall_block"| FW
    PARSE -->|"isolate_host"| ISO
    PARSE -->|"patch"| PATCH
    PARSE -->|"notify"| ALERT
    PARSE -->|"deep_inspect"| HUNT

    FW & ISO & PATCH & ALERT & HUNT --> RES
```

---

## 10. Failure Handling & Agent Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Processing: alert received
    Processing --> AwaitingSubAgents: dispatch CVE + Asset agents
    AwaitingSubAgents --> Aggregating: all results received
    AwaitingSubAgents --> Timeout: agent timeout (30s)
    Timeout --> Aggregating: proceed with partial results
    Aggregating --> Planning: invoke LLM
    Planning --> AwaitingApproval: plans published
    AwaitingApproval --> Executing: analyst approved
    AwaitingApproval --> Escalated: approval timeout (15 min)
    AwaitingApproval --> Closed: analyst rejected
    Executing --> Completed: all actions succeeded
    Executing --> PartialFailure: some actions failed
    PartialFailure --> AwaitingApproval: re-plan with failure context
    Completed --> Idle: incident logged
    Escalated --> Idle: manual takeover logged
    Closed --> Idle: rejection logged
```

---

## 11. Technology Stack Summary

| Component | Technology | Rationale |
|---|---|---|
| **Orchestrator / Agents** | Python 3.12 + `asyncio` | Consistent with existing codebase, async-native for concurrent sub-agents |
| **Agent Framework** | LangGraph or custom state machine | Structured agent orchestration with explicit state transitions |
| **LLM (Planning)** | Fine-tuned Llama 3 / Mistral (via vLLM or Ollama) | Local deployment, no data leaves the network, tuned on incident response playbooks |
| **Inter-layer messaging** | Apache Kafka (existing) | Already in stack, durable, auditable |
| **Intra-agent messaging** | Redis 7 Streams + pub/sub | Low-latency task dispatch, heartbeats, session state |
| **CVE Database** | PostgreSQL + NVD mirror (synced nightly) | Offline-capable, fast full-text search on CVE descriptions |
| **Asset Inventory** | PostgreSQL | Existing CMDB or custom schema for hosts, services, network zones |
| **Incident History** | PostgreSQL | Queryable log for historical context used by planning agent |
| **SOC Dashboard** | Extend existing FastAPI + WebSocket | Reuse Layer 1 dashboard, add approval UI |
| **Execution Layer** | Python + Ansible/Salt + REST APIs | Firewall rules, host isolation, patching, alerting via existing infra tooling |
| **Containerisation** | Docker Compose (dev) / Kubernetes (prod) | Consistent with existing deployment model |

---

## 12. Directory Structure (Proposed)

```
Sentinel/
├── capture/                          ← existing
├── ingestion/                        ← existing (Layer 1)
├── hybrid-detection/                 ← Layer 2 (to be built)
│   ├── models/
│   │   ├── autoencoder.py
│   │   └── random_forest.py
│   ├── ensemble.py
│   ├── consumer.py                   ← Kafka consumer for network-features
│   └── producer.py                   ← Kafka producer for anomaly-alerts
├── agentic/                          ← Layer 3 (this design)
│   ├── orchestrator/
│   │   ├── agent.py                  ← main orchestrator loop
│   │   ├── triage.py                 ← alert triage & prioritisation
│   │   └── dispatcher.py             ← sub-agent task dispatch
│   ├── agents/
│   │   ├── cve_lookup.py             ← CVE/NVD query agent
│   │   ├── asset_discovery.py        ← asset inventory query agent
│   │   └── base.py                   ← shared agent interface
│   ├── planning/
│   │   ├── context_builder.py        ← assembles LLM prompt context
│   │   ├── llm_client.py             ← fine-tuned LLM interface
│   │   ├── plan_ranker.py            ← confidence scoring & ranking
│   │   └── prompts/
│   │       └── threat_response.jinja ← structured prompt template
│   ├── state/
│   │   ├── redis_client.py           ← Redis connection + helpers
│   │   └── session.py                ← per-incident session state
│   ├── kafka/
│   │   ├── consumer.py               ← anomaly-alerts consumer
│   │   └── producer.py               ← execution-plans producer
│   ├── models/                       ← Pydantic schemas
│   │   ├── alert.py
│   │   ├── plan.py
│   │   └── asset.py
│   ├── Dockerfile
│   └── requirements.txt
├── execution/                        ← Layer 4
│   ├── router.py                     ← action type → executor mapping
│   ├── executors/
│   │   ├── firewall.py
│   │   ├── isolator.py
│   │   ├── patcher.py
│   │   └── notifier.py
│   ├── kafka/
│   │   ├── consumer.py               ← approved-actions consumer
│   │   └── producer.py               ← action-results producer
│   ├── Dockerfile
│   └── requirements.txt
├── dashboard/                        ← existing (extended for approval UI)
├── docs/architecture/
│   └── AGENTIC_LAYER.md              ← this document
└── docker-compose.yml                ← extended with new services
```
