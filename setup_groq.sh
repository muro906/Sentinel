#!/bin/bash
# Setup script for Groq Cloud API integration with Sentinel

echo "🚀 Setting up Sentinel with Groq Cloud API"
echo "=========================================="

# Check if GROQ_API_KEY is already set
if [ -n "$GROQ_API_KEY" ]; then
    echo "✅ GROQ_API_KEY is already set"
else
    echo ""
    echo "📋 To get your Groq API key:"
    echo "1. Go to https://console.groq.com/"
    echo "2. Sign up for a free account"
    echo "3. Navigate to API Keys section"
    echo "4. Create a new API key"
    echo ""
    read -p "🔑 Enter your Groq API key: " GROQ_API_KEY
    
    if [ -z "$GROQ_API_KEY" ]; then
        echo "❌ No API key provided. Exiting."
        exit 1
    fi
    
    # Add to .env file
    echo "GROQ_API_KEY=$GROQ_API_KEY" >> .env
    echo "✅ API key saved to .env file"
fi

echo ""
echo "🔧 Configuration updated:"
echo "- LLM Provider: Groq Cloud"
echo "- Model: llama-3.1-8b-instant"
echo "- Base URL: https://api.groq.com/openai/v1"
echo ""
echo "🎯 Benefits of using Groq Cloud:"
echo "- ⚡ Ultra-fast inference (300+ tokens/second)"
echo "- 💰 Generous free tier (30 requests/minute)"
echo "- 🧠 High-quality Llama 3.1 models"
echo "- 📦 Zero local storage required"
echo "- 🔄 Automatic scaling and reliability"
echo ""
echo "🐳 Starting services..."
docker compose up -d postgres redis kafka

echo ""
echo "✅ Setup complete! You can now start the orchestrator:"
echo "   docker compose up orchestrator"
