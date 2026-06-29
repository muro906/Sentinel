"""
Simple test alert publisher - runs inside the orchestrator container.
"""
import json
import time
import uuid
from datetime import datetime, timezone
from confluent_kafka import Producer

KAFKA_BOOTSTRAP = "kafka:9092"
TOPIC = "anomaly-alerts"

def make_test_alert():
    return {
        "alert_id": f"alert-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "anomaly_score": 0.91,
        "classification": "port_scan",
        "feature_vector": {
            "uid": f"C{uuid.uuid4().hex[:16]}",
            "ts": str(time.time()),
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

if __name__ == "__main__":
    producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP})
    alert = make_test_alert()
    
    key = alert["alert_id"].encode("utf-8")
    value = json.dumps(alert).encode("utf-8")
    
    producer.produce(TOPIC, key=key, value=value)
    producer.flush()
    
    print(f"Sent test alert: {alert['alert_id']}")
