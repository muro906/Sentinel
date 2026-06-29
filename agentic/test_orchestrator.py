"""
Test script for the simplified orchestrator.
Simulates an alert and processes it through the graph.
"""
import asyncio
import json
import sys
from datetime import datetime, timezone
from graph import process_alert


def make_test_alert() -> dict:
    """Create a test alert matching detection service format."""
    return {
        "alert_id": "test-alert-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "anomaly_score": 0.91,
        "classification": "port_scan",
        "feature_vector": {
            "uid": "C1234567890abcdef",
            "ts": str(datetime.now(timezone.utc).timestamp()),
            "src_ip": "172.16.0.55",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "proto": "tcp",
            "service": "ssh",
            "duration": 0.001,
            "orig_bytes": 64,
            "resp_bytes": 0,
            "orig_pkts": 1,
            "resp_pkts": 0,
            "conn_state": "S0",
        },
        "model_votes": [
            {
                "model_name": "et_ssl",
                "score": 0.91,
                "label": "port_scan",
                "confidence": 0.91
            }
        ],
    }


async def main():
    """Test the orchestrator with a simulated alert."""
    print("=" * 60)
    print("Testing Simplified Orchestrator")
    print("=" * 60)
    
    # Create test alert
    alert = make_test_alert()
    print(f"\nTest Alert:")
    print(f"  ID: {alert['alert_id']}")
    print(f"  Classification: {alert['classification']}")
    print(f"  Source: {alert['feature_vector']['src_ip']}")
    print(f"  Destination: {alert['feature_vector']['dst_ip']}:{alert['feature_vector']['dst_port']}")
    print(f"  Anomaly Score: {alert['anomaly_score']}")
    
    # Process through graph
    print("\nProcessing through LangGraph...")
    try:
        result = await process_alert(alert)
        
        print("\n" + "=" * 60)
        print("Processing Complete")
        print("=" * 60)
        print(f"Status: {result.get('status')}")
        print(f"Error: {result.get('error', 'None')}")
        
        # Show asset context
        asset_ctx = result.get('asset_context', {})
        if asset_ctx:
            print("\nAsset Context:")
            for key, value in asset_ctx.items():
                if value:
                    print(f"  {key}: {value}")
        
        # Show CVE matches
        cves = result.get('cve_matches', [])
        print(f"\nCVE Matches: {len(cves)}")
        for cve in cves[:3]:
            print(f"  - {cve.get('cve_id')}: CVSS {cve.get('cvss_v3_score', 'N/A')}")
        
        # Show plans
        plans = result.get('plans', [])
        print(f"\nGenerated Plans: {len(plans)}")
        for i, plan in enumerate(plans, 1):
            print(f"\n  Plan {i}:")
            print(f"    ID: {plan.get('plan_id')}")
            print(f"    Confidence: {plan.get('confidence')}")
            print(f"    Risk Level: {plan.get('risk_level')}")
            print(f"    Aggression: {plan.get('aggression')}")
            print(f"    Summary: {plan.get('threat_summary')}")
            print(f"    Actions:")
            for action in plan.get('actions', []):
                print(f"      - {action.get('type')}: {action.get('target')}")
        
        print("\n" + "=" * 60)
        print("Test Successful!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nTest Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
