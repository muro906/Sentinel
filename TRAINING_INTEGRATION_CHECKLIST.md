# Training Model Integration Checklist

## 🎯 Overview
Use this checklist to prepare your trained detection model for integration with the Sentinel agentic system.

## 📋 Model Preparation

### ✅ Model Files Required
Copy these files to `detection-service/models/` after training:

- [ ] **`encoder_weights.pt`** - Trained autoencoder weights
- [ ] **`scaler.joblib`** - Feature scaling parameters  
- [ ] **`centroid.npy`** - Normal behavior centroid
- [ ] **`model_meta.json`** - Model metadata and configuration

### ✅ Model Metadata Format
Create `model_meta.json` with this structure:
```json
{
  "model_version": "1.0.0",
  "training_date": "2024-01-15",
  "feature_dimensions": 20,
  "encoder_layers": [64, 32, 16],
  "latent_dim": 8,
  "threshold": 0.85,
  "training_samples": 100000,
  "validation_accuracy": 0.92,
  "false_positive_rate": 0.08,
  "description": "ET-SSL anomaly detection model"
}
```

## 🔧 Configuration Settings

### ✅ Detection Service Environment
Update these settings in `docker-compose.yml`:
```yaml
detection-service:
  environment:
    ANOMALY_THRESHOLD: "0.85"  # Set based on your validation results
    MODEL_DIR: "/models"
    LOG_LEVEL: "INFO"
    # Optional: Override EMA update frequency
    EMA_UPDATE_EVERY: "1000"
```

### ✅ Threshold Calibration
Based on your validation results, set:
- [ ] **ANOMALY_THRESHOLD** - Balance false positives vs false negatives
- [ ] **EMA_UPDATE_EVERY** - How often to update normal behavior centroid
- [ ] **MIN_ANOMALY_SCORE** - Minimum score for agentic processing

## 🧪 Validation Steps

### ✅ Model Loading Test
```bash
# Test model loads correctly
docker compose run --rm detection-service python -c "
import torch
import joblib
import numpy as np
from pathlib import Path

# Load model components
encoder = torch.load('/models/encoder_weights.pt', map_location='cpu')
scaler = joblib.load('/models/scaler.joblib')
centroid = np.load('/models/centroid.npy')

print(f'✅ Encoder loaded: {type(encoder)}')
print(f'✅ Scaler loaded: {type(scaler)}')
print(f'✅ Centroid loaded: {centroid.shape}')
print('✅ All model components loaded successfully!')
"
```

### ✅ Feature Vector Test
```bash
# Test feature vector processing
docker compose run --rm detection-service python -c "
import numpy as np
import joblib
from pathlib import Path

# Load scaler
scaler = joblib.load('/models/scaler.joblib')

# Create test feature vector (20 dimensions)
test_features = np.random.rand(1, 20)

# Scale features
scaled = scaler.transform(test_features)

print(f'✅ Feature shape: {test_features.shape}')
print(f'✅ Scaled shape: {scaled.shape}')
print('✅ Feature processing works!')
"
```

## 📊 Performance Benchmarks

### ✅ Expected Performance Metrics
Your trained model should achieve:

- [ ] **Processing Speed** < 10ms per feature vector
- [ ] **Memory Usage** < 500MB per detection service instance
- [ ] **Accuracy** > 90% on validation set
- [ ] **False Positive Rate** < 15%

### ✅ Load Testing
```bash
# Test with synthetic data
python scripts/generate_test_features.py --samples 1000 --output test_features.json

# Process through detection service
docker compose run --rm detection-service python scripts/test_model_performance.py --input test_features.json
```

## 🔍 Integration Testing

### ✅ End-to-End Flow Test
1. [ ] **Start Infrastructure**
   ```bash
   docker compose up -d postgres redis kafka
   ```

2. [ ] **Start Detection Service**
   ```bash
   docker compose up -d detection-service
   ```

3. [ ] **Generate Test Features**
   ```bash
   python scripts/simulate_network_features.py --count 100 --anomaly-ratio 0.1
   ```

4. [ ] **Verify Alert Generation**
   ```bash
   # Monitor anomaly-alerts topic
   docker exec sentinel-kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic anomaly-alerts --from-beginning
   ```

5. [ ] **Start Agentic Layer**
   ```bash
   docker compose up -d orchestrator
   ```

6. [ ] **Verify Plan Generation**
   ```bash
   # Monitor execution-plans topic
   docker exec sentinel-kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic execution-plans --from-beginning
   ```

## 🚨 Troubleshooting Guide

### Common Issues & Solutions

#### Issue: Model fails to load
**Symptoms:** Detection service crashes on startup
**Solutions:**
- Check file permissions in `detection-service/models/`
- Verify PyTorch version compatibility
- Ensure model files are not corrupted

#### Issue: No alerts generated
**Symptoms:** Features processed but no anomaly alerts
**Solutions:**
- Lower `ANOMALY_THRESHOLD` value
- Check feature vector format (20 dimensions)
- Verify scaling parameters match training

#### Issue: High false positive rate
**Symptoms:** Too many alerts for normal traffic
**Solutions:**
- Increase `ANOMALY_THRESHOLD`
- Retrain model with more normal traffic data
- Adjust feature engineering

#### Issue: Poor performance
**Symptoms:** Slow processing, high memory usage
**Solutions:**
- Optimize model architecture
- Use GPU acceleration if available
- Scale horizontally with multiple instances

## 📈 Monitoring Setup

### ✅ Key Metrics to Track
- [ ] **Alert Rate** - Alerts per minute
- [ ] **Processing Latency** - Time from feature to alert
- [ ] **False Positive Rate** - Invalid alerts percentage
- [ ] **Model Confidence** - Average anomaly scores

### ✅ Alerting Rules
Set up monitoring for:
- Detection service downtime
- Alert rate anomalies (sudden spikes/drops)
- High error rates in agentic processing
- Kafka consumer lag

## 🔄 Model Updates

### ✅ Version Management
- [ ] **Model Versioning** - Use semantic versioning
- [ ] **Rollback Plan** - Keep previous model version
- [ ] **A/B Testing** - Compare new vs old model performance

### ✅ Deployment Process
1. Train and validate new model
2. Update model files in `detection-service/models/`
3. Update `model_meta.json` with new version
4. Deploy to staging environment
5. Run integration tests
6. Deploy to production
7. Monitor performance metrics

## ✅ Final Integration Checklist

Before going live, verify:

- [ ] All model files copied to correct location
- [ ] Detection service starts without errors
- [ ] Feature vectors processed correctly
- [ ] Anomaly alerts generated for test data
- [ ] Agentic layer processes alerts successfully
- [ ] Plans generated via Groq Cloud API
- [ ] Dashboard displays alerts and plans
- [ ] End-to-end flow works end-to-end

## 🎯 Ready for Production!

Once you complete this checklist and all tests pass, your Sentinel system will be ready for production deployment with:

- **Real-time anomaly detection**
- **AI-powered threat response planning**
- **Automated investigation workflows**
- **Human oversight and approval**
- **Complete audit trails**

---

**Next Steps:**
1. Complete your model training
2. Follow this integration checklist
3. Run the full integration tests
4. Deploy to production!

🚀 Your AI-powered security operations center awaits!
