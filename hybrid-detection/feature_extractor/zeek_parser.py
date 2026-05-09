"""
Parse Zeek conn.log JSON messages from kafka network-features topic
Normalize field names to match those expected in build_feature_vector()

"""
import json
import logging

logger = logging.getLogger("sentinel.zeek_parser.")

def parse_kafka_messages(raw_value:bytes) -> dict:

    """
    Deserialize a Kafka message from the network-features topic.

    Returns:
        dict with unified field names, or None if message is malformed
    
    The Zeek JSON format uses field names like uid, ts, id.orig_h, id.resp_h, etc.
    We normalize these to match the feature vector expectations.
    
    """
    try:
        raw = json.loads(raw_value.decode("utf-8"))
    except UnicodeDecodeError as e:
        logger.error(f"Malformed Kafka message, Skipping {e}")
        return None

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from Kafka message: {e}")
        return None

    # Mapping of Zeek's fields to flat names
    record = {
        "uid": raw.get("uid", ""),
        "timestamp": raw.get("ts", ""),
        "src_ip": raw.get("id.orig_h", raw.get("src_ip", "")),
        "src_port": raw.get("id.orig_p", raw.get("src_port", 0)),
        "dst_ip": raw.get("id.resp_h", raw.get("dst_ip", "")),
        "dst_port": raw.get("id.resp_p", raw.get("dst_port", 0)),
        "proto": raw.get("proto", ""),
        "service": raw.get("service", ""),
        "duration": raw.get("duration", 0),
        "orig_bytes": raw.get("orig_bytes", 0),
        "resp_bytes": raw.get("resp_bytes", 0),
        "orig_pkts": raw.get("orig_pkts", 0),
        "resp_pkts": raw.get("resp_pkts", 0),
        "conn_state": raw.get("conn_state", "OTH"),
        "ssl_version": raw.get("ssl_version", None),
        "dns_query": raw.get("dns_query", None),
    }
    return record
    