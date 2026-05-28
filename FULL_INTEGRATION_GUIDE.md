# Sentinel Agentic Layer - Full Integration Guide

## 🎯 Overview
This guide covers connecting all components of the Sentinel system after training your detection model. The agentic layer is fully implemented and ready for production deployment.

## 📋 Prerequisites Checklist

### ✅ Completed Components
- [x] **Agentic Layer** - Full orchestration system with Kafka integration
- [x] **Groq Cloud API** - LLM integration for plan generation
- [x] **Multi-Agent System** - CVE lookup + Asset discovery agents
- [x] **RAG System** - Historical incident retrieval for context
- [x] **Reasoning Traces** - Complete audit trail system
- [x] **Execution Framework** - Action executors with human oversight
- [x] **Database Schema** - All tables and migrations ready
- [x] **Docker Configuration** - Full stack orchestration

### 🔄 Training Model Integration
- [ ] **Trained Model Files** - Place in `detection-service/models/`
- [ ] **Model Configuration** - Update detection service settings
- [ ] **Threshold Calibration** - Set anomaly detection thresholds

## 🚀 Step-by-Step Integration

### Step 1: Model Deployment
```bash
# After training, copy your model artifacts to:
detection-service/models/
├── encoder_weights.pt
├── scaler.joblib
├── centroid.npy
└── model_meta.json
```

### Step 2: Environment Setup
```bash
# Set up your API keys
./setup_groq.sh

# Create .env file with required variables
cat > .env << EOF
GROQ_API_KEY=your_groq_api_key_here
POSTGRES_PASSWORD=sentinel_dev
JWT_SECRET_KEY=your_jwt_secret_here
EOF
```

### Step 3: Start Infrastructure Services
```bash
# Start core services
docker compose up -d postgres redis kafka

# Verify services are healthy
docker compose ps
```

### Step 4: Initialize Database
```bash
# Database migrations run automatically via docker-entrypoint-initdb.d
# Verify tables exist:
docker exec sentinel-postgres psql -U sentinel -d sentinel -c "\dt"
```

### Step 5: Start Detection Service
```bash
# Start the anomaly detection service
docker compose up -d detection-service

# Verify it's consuming from network-features topic
docker logs sentinel-detection-service
```

### Step 6: Start Agentic Layer
```bash
# Start the orchestrator
docker compose up -d orchestrator

# Verify it's ready to process alerts
docker logs sentinel-orchestrator
```

### Step 7: Start Dashboard
```bash
# Start the full dashboard stack
docker compose up -d dashboard-backend gateway

# Access at https://sentinel.local (or http://localhost)
```

## 🔄 Complete Data Flow

### 1. Data Ingestion
```
Network Traffic → Zeek → Feature Extractor → Kafka[network-features]
```

### 2. Anomaly Detection
```
Kafka[network-features] → Detection Service → Kafka[anomaly-alerts]
```

### 3. Agentic Processing
```
Kafka[anomaly-alerts] → Orchestrator → 
├── CVE Lookup Agent → NVD Database
├── Asset Discovery Agent → Asset Database
└── LLM (Groq Cloud) → Execution Plans
```

### 4. Human Review & Execution
```
Kafka[execution-plans] → Dashboard → Analyst Approval → 
Kafka[approved-actions] → Action Executors → Kafka[action-results]
```

## 🧪 Testing the Full System

### Test 1: Simulate Network Traffic
```bash
# Use existing test data or generate new traffic
python scripts/simulate_alerts.py --count 5 --type exploit_attempt
```

### Test 2: Verify Alert Processing
```bash
# Check Kafka topics
docker exec sentinel-kafka kafka-topics --bootstrap-server localhost:9092 --list

# Monitor anomaly alerts
docker exec sentinel-kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic anomaly-alerts --from-beginning
```

### Test 3: Check Dashboard Integration
- Access the dashboard
- Review incoming alerts
- Approve/reject plans
- Verify execution results

## 🔧 Configuration Options

### Detection Service Settings
```yaml
# In docker-compose.yml under detection-service:
environment:
  ANOMALY_THRESHOLD: "0.85"  # Adjust based on your model's performance
  EMA_UPDATE_EVERY: "1000"    # Centroid update frequency
  MODEL_DIR: "/models"
```

### Agentic Layer Settings
```yaml
# In docker-compose.yml under orchestrator:
environment:
  MIN_ANOMALY_SCORE: "0.5"     # Minimum score to process
  NUM_PLANS: "3"               # Number of plans to generate
  APPROVAL_TIMEOUT: "600"       # Approval timeout in seconds
```

### LLM Settings
```yaml
environment:
  LLM_MODEL: "llama-3.1-8b-instant"  # Fast inference model
  LLM_TEMPERATURE: "0.7"              # Creativity level
```

## 📊 Monitoring & Troubleshooting

### Key Logs to Monitor
```bash
# Detection service
docker logs -f sentinel-detection-service

# Orchestrator
docker logs -f sentinel-orchestrator

# Dashboard backend
docker logs -f sentinel-dashboard-backend
```

### Common Issues & Solutions

#### Issue: No alerts being generated
**Check:**
- Network traffic ingestion (Zeek logs)
- Feature extractor output
- Detection service model loading

#### Issue: Plans not being generated
**Check:**
- Groq API key validity
- LLM service connectivity
- Agent results in Redis

#### Issue: Actions not executing
**Check:**
- Dashboard approval workflow
- Kafka topic connectivity
- Executor permissions

## 🎯 Performance Tuning

### Detection Service
- Adjust `ANOMALY_THRESHOLD` based on false positive rate
- Tune `EMA_UPDATE_EVERY` for concept drift handling

### Agentic Layer
- Modify agent timeouts for complex investigations
- Adjust plan generation limits for throughput

### Database
- Monitor PostgreSQL connection pool usage
- Optimize indexes for query patterns

## 📈 Scaling Considerations

### Horizontal Scaling
- Multiple detection service instances
- Orchestrator partitioning by alert type
- Database read replicas for dashboard queries

### Resource Requirements
- **Detection Service**: 2 CPU, 4GB RAM per instance
- **Orchestrator**: 1 CPU, 2GB RAM per instance
- **PostgreSQL**: 4 CPU, 8GB RAM, SSD storage
- **Redis**: 1 CPU, 2GB RAM
- **Kafka**: 2 CPU, 4GB RAM per broker

## 🔒 Security Considerations

### Network Security
- Kafka SASL/SSL authentication
- Database connection encryption
- API rate limiting

### Data Protection
- PII redaction in logs
- Encrypted sensitive data at rest
- Access control for dashboard

### Operational Security
- Regular security updates
- Audit log retention
- Incident response procedures

## 🎉 Success Metrics

### System Performance
- Alert processing latency < 30 seconds
- Plan generation time < 5 seconds
- False positive rate < 10%

### Operational Efficiency
- Analyst workload reduction > 50%
- Mean time to response < 5 minutes
- Automated containment rate > 70%

## 📞 Support & Maintenance

### Regular Tasks
- Monitor system health daily
- Review and retune models monthly
- Update CVE database weekly
- Backup database and configurations

### Emergency Procedures
- Service restart procedures
- Database recovery processes
- Rollback plans for deployments

---

## 🚀 You're Ready!

Once you complete your model training and follow these steps, you'll have a fully operational AI-powered security operations center with:

- **Real-time threat detection**
- **Automated investigation**
- **AI-generated response plans**
- **Human-in-the-loop oversight**
- **Complete audit trails**

The Sentinel agentic layer is production-ready and waiting for your trained model! 🎯
