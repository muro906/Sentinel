# Simplified Agentic Layer

A simplified LangGraph-based orchestrator for the Sentinel security platform. This layer receives anomaly alerts from the detection service, gathers context using agents, generates remediation plans using Groq LLM, and publishes them for human approval.

## Architecture

### 4-Node LangGraph Pipeline

1. **receive_alert** - Parse and validate incoming Kafka alert
2. **dispatch_agents** - Run asset discovery + CVE lookup in parallel
3. **generate_plans** - Call Groq LLM for remediation plans
4. **publish_plans** - Store in PostgreSQL, publish to Kafka

### Agents

#### Asset Discovery Agent
Performs network reconnaissance using local commands:
- `ping` - Check host reachability
- `nslookup` - Resolve hostname from IP
- `whois` - Get IP ownership information
- Local asset database lookup

#### CVE Lookup Agent
Queries the local PostgreSQL CVE database:
- Matches by port → service mapping
- Searches by attack pattern
- Returns top 5 relevant CVEs with CVSS scores

#### LLM Plan Generation (Groq)
Uses Groq API to generate remediation plans:
- Input: alert data + asset context + CVE matches
- Output: 2-3 plans with different aggression levels
- Actions: notify, investigate, block_ip

## Setup

### Prerequisites
- Docker and Docker Compose
- Groq API key (get from https://console.groq.com/)
- PostgreSQL database with CVE entries

### Environment Variables

```bash
# Required
GROQ_API_KEY=your_groq_api_key_here
POSTGRES_PASSWORD=your_database_password

# Optional
GROQ_MODEL=llama-3.1-8b-instant
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
LOG_LEVEL=INFO
```

### Running with Docker Compose

```bash
# Start all services
docker-compose up -d orchestrator

# View logs
docker-compose logs -f orchestrator
```

### Running Locally (for development)

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GROQ_API_KEY=your_key
export DATABASE_URL=postgresql://sentinel:password@localhost:5432/sentinel
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# Run the orchestrator
python main.py
```

## Testing

### Test with Simulated Alert

```bash
# Run the test script (requires local Kafka and PostgreSQL)
python test_orchestrator.py
```

This will:
1. Create a test port scan alert
2. Process it through the LangGraph
3. Display asset context, CVE matches, and generated plans

### Test with Real Kafka Flow

```bash
# Start the full stack
docker-compose up -d

# Send a test alert
python ../scripts/simulate_alerts.py --type port_scan

# View orchestrator logs
docker-compose logs -f orchestrator
```

## Flow Diagram

```
Detection Service
       ↓
Kafka: anomaly-alerts
       ↓
Orchestrator (LangGraph)
       ├─→ Asset Discovery Agent (ping, nslookup, whois)
       ├─→ CVE Lookup Agent (PostgreSQL query)
       ↓
Groq LLM (plan generation)
       ↓
Kafka: execution-plans
       ↓
Dashboard Backend (PostgreSQL storage)
       ↓
Frontend (analyst review & approval)
```

## Plan Structure

Generated plans include:
- `plan_id` - Unique identifier
- `confidence` - 0-1 score
- `risk_level` - low/medium/high
- `aggression` - conservative/moderate/aggressive
- `threat_summary` - Brief description
- `actions` - List of remediation steps

### Action Types

- **notify** - Send notification to security team
- **investigate** - Collect more information (logs, traffic)
- **block_ip** - Block source IP at firewall

## Database Schema

Plans are stored in the `incidents` table:
```sql
ALTER TABLE incidents ADD COLUMN plans_generated JSONB;
```

## Troubleshooting

### LLM Fails
- Check GROQ_API_KEY is set correctly
- Verify network connectivity to api.groq.com
- Check logs for specific error messages

### Asset Discovery Fails
- Ensure network tools are installed (ping, nslookup, whois)
- Check container has network access
- Verify target IPs are reachable

### CVE Lookup Returns Empty
- Ensure CVE database is populated
- Check database connection string
- Verify service/port mappings are correct

## Key Differences from Complex Version

This simplified version removes:
- Complex reasoning trace system (Redis/PostgreSQL)
- 7+ node LangGraph (reduced to 4)
- Abstract agent base classes
- Sophisticated plan ranking
- Auto-execution tier logic
- Re-planning on failure

Benefits:
- Implementable in 2 hours
- Easier to understand and debug
- Sufficient for demonstration
- Can be extended later if needed
