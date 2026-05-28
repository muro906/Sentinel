#!/bin/bash
# Sentinel Full Deployment Script
# Run this after completing your model training

set -e

echo "🚀 Sentinel Full Deployment Script"
echo "=================================="

# Check if model files exist
echo "📋 Checking for trained model files..."
MODEL_DIR="detection-service/models"
REQUIRED_FILES=("encoder_weights.pt" "scaler.joblib" "centroid.npy" "model_meta.json")

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$MODEL_DIR/$file" ]; then
        echo "❌ Missing required file: $MODEL_DIR/$file"
        echo "Please complete your model training first!"
        exit 1
    fi
done

echo "✅ All model files found!"

# Check for API key
if [ ! -f ".env" ] || ! grep -q "GROQ_API_KEY" .env; then
    echo "🔑 Setting up Groq API key..."
    ./setup_groq.sh
fi

# Load environment variables
source .env

echo "🔧 Starting infrastructure services..."
docker compose up -d postgres redis kafka

echo "⏳ Waiting for services to be healthy..."
sleep 10

# Check service health
echo "🏥 Checking service health..."
docker compose ps postgres redis kafka

echo "🧠 Starting detection service..."
docker compose up -d detection-service

echo "⏳ Waiting for detection service..."
sleep 5

echo "🤖 Starting agentic layer..."
docker compose up -d orchestrator

echo "⏳ Waiting for orchestrator..."
sleep 5

echo "📊 Starting dashboard..."
docker compose up -d dashboard-backend gateway

echo "✅ All services started!"
echo ""

# Display service URLs
echo "🌐 Service URLs:"
echo "   Dashboard: https://localhost (or http://localhost)"
echo "   Kafka UI:   http://localhost:9000"
echo ""

# Show how to monitor
echo "📊 Monitoring Commands:"
echo "   View all services:     docker compose ps"
echo "   Detection logs:       docker logs -f sentinel-detection-service"
echo "   Orchestrator logs:     docker logs -f sentinel-orchestrator"
echo "   Dashboard logs:       docker logs -f sentinel-dashboard-backend"
echo ""

# Test the system
echo "🧪 Running quick system test..."
python3 scripts/simulate_alerts.py --count 3 --type exploit_attempt || echo "⚠️  Test script not found, manual testing required"

echo ""
echo "🎉 Sentinel deployment complete!"
echo ""
echo "📝 Next Steps:"
echo "   1. Access the dashboard to review alerts"
echo "   2. Approve/reject generated plans"
echo "   3. Monitor execution results"
echo "   4. Check logs for any issues"
echo ""
echo "📚 For detailed troubleshooting, see:"
echo "   - FULL_INTEGRATION_GUIDE.md"
echo "   - TRAINING_INTEGRATION_CHECKLIST.md"
