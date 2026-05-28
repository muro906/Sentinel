#!/usr/bin/env python3
"""
Test script to verify Groq Cloud API integration with Sentinel.
This tests the LLM client directly with a simple request.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone

# Add agentic modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'agentic'))

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger(__name__)

async def test_groq_api():
    """Test direct connection to Groq Cloud API."""
    logger.info("Testing Groq Cloud API connection...")
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        logger.error("❌ GROQ_API_KEY not found in environment variables")
        logger.info("Please set up your API key using: ./setup_groq.sh")
        return False
    
    logger.info(f"✅ API key found: {api_key[:10]}...{api_key[-4:]}")
    
    try:
        # Import the LLM client
        from agentic.planning.llm_client import generate_plans
        
        # Create a simple test prompt
        test_prompt = """[INST]
You are a cybersecurity expert. Generate a simple response plan for this scenario:

SCENARIO: Suspicious login attempt detected from IP 192.168.1.100 to server 10.0.0.5

Generate exactly 1 plan with this JSON format:
{
  "plans": [
    {
      "plan_id": "test-001",
      "confidence": 0.8,
      "risk_level": "medium",
      "aggression": "moderate",
      "threat_summary": "Brief description of the threat and response",
      "actions": [
        {
          "type": "notify",
          "target": "security-team",
          "params": {},
          "rationale": "Alert the security team",
          "reversible": true,
          "estimated_duration_seconds": 5
        }
      ]
    }
  ]
}
[/INST]"""
        
        logger.info("🚀 Sending test request to Groq Cloud...")
        logger.info(f"📝 Prompt length: {len(test_prompt)} characters")
        
        # Make the API call
        plans, raw_response = await generate_plans(test_prompt, "test-alert-001")
        
        logger.info("✅ API call successful!")
        logger.info(f"📊 Generated {len(plans)} plans")
        logger.info(f"📄 Raw response length: {len(raw_response)} characters")
        
        # Display the results
        if plans:
            plan = plans[0]
            logger.info("🎯 Generated Plan:")
            logger.info(f"   Plan ID: {plan.get('plan_id')}")
            logger.info(f"   Confidence: {plan.get('confidence')}")
            logger.info(f"   Risk Level: {plan.get('risk_level')}")
            logger.info(f"   Aggression: {plan.get('aggression')}")
            logger.info(f"   Summary: {plan.get('threat_summary')}")
            logger.info(f"   Actions: {len(plan.get('actions', []))} action(s)")
            
            for i, action in enumerate(plan.get('actions', []), 1):
                logger.info(f"     {i}. {action.get('type')} → {action.get('target')}")
        
        logger.info("🔍 Raw Response Preview:")
        logger.info(f"   {raw_response[:200]}...")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ API call failed: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        
        # Provide helpful troubleshooting
        if "401" in str(e):
            logger.error("🔑 Authentication failed - check your API key")
        elif "429" in str(e):
            logger.error("⏱️ Rate limit exceeded - wait a moment and try again")
        elif "timeout" in str(e).lower():
            logger.error("⏰ Request timed out - check your network connection")
        else:
            logger.error("🌐 Network or API error - check your connection")
        
        return False

async def test_model_info():
    """Test getting available models from Groq."""
    logger.info("🔍 Checking Groq model availability...")
    
    try:
        from openai import AsyncOpenAI
        
        # Load API key
        from dotenv import load_dotenv
        load_dotenv()
        api_key = os.environ.get("GROQ_API_KEY")
        
        client = AsyncOpenAI(
            base_url="https://api.groq.com/openai/v1",
            api_key=api_key,
        )
        
        # Get available models
        models = await client.models.list()
        
        logger.info("✅ Available Groq models:")
        for model in models.data:
            if "llama" in model.id.lower() or "mixtral" in model.id.lower():
                logger.info(f"   📱 {model.id}")
        
        return True
        
    except Exception as e:
        logger.warning(f"⚠️ Could not fetch models: {e}")
        return False

async def main():
    """Run all Groq API tests."""
    logger.info("🧪 Starting Groq Cloud API Tests")
    logger.info("=" * 50)
    
    # Test model availability
    await test_model_info()
    
    print()
    
    # Test actual API call
    success = await test_groq_api()
    
    print()
    logger.info("=" * 50)
    
    if success:
        logger.info("🎉 All Groq API tests passed!")
        logger.info("✅ Your Sentinel agentic system is ready to use Groq Cloud")
        logger.info("")
        logger.info("🚀 Next steps:")
        logger.info("   1. Start services: docker compose up -d postgres redis kafka")
        logger.info("   2. Run orchestrator: docker compose up orchestrator")
        logger.info("   3. Send test alerts to see the full pipeline in action")
    else:
        logger.error("❌ Groq API tests failed")
        logger.error("🔧 Please check your API key and network connection")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
