"""
The function converts a raw Zeek log entry (dict) into a 20-dimensional feature vector that the ET-SSL model expects.

Called by: 
- notebooks: to build numpy arrays from the dataset csv/parquet files
- detection_service: to build tensors from live Kafka messages
"""

import numpy as np
import math
from config.constants import FEATURE_DIM

CONN_STATES = ["SF", "S0", "REJ", "RSTO", "RSTR", "OTH"]

def build_feature_vector(record: dict) -> np.ndarray:
    """
    Build a float32 feature vector of shape (20, ) from a conn.log record.

    Args:
        record: A dict with keys matching Zeek conn.log field names or unified names from the column maps

    Returns:
        np.ndarray of shape (FEATURE_DIM, ) with dtype float32 
    
    Steps:
    1. Extract scalar fields with safe results
    2. Derive ratio/rate features
    3. Apply log1p transforms
    4. Build one-hot vectors for conn_state
    5. Build binary protocol flags
    6. Concatenate into final feature vector
    7. Replace NaN/Inf with 0
    """

    # 1. Raw field extraction
    duration = float(record.get("duration", 0.0)) or 0
    orig_bytes = float(record.get("orig_bytes", 0)) or 0
    resp_bytes = float(record.get("resp_bytes", 0)) or 0
    orig_pkts = float(record.get("orig_pkts", 0)) or 0
    resp_pkts = float(record.get("resp_pkts", 0)) or 0
    proto = str(record.get("proto", "").lower())
    conn_state = str(record.get("conn_state", "OTH") or "OTH").upper()
    service = str(record.get("service", "") or "").lower()
    dst_port = int(record.get("dst_port", 0)) or 0

    # 2. Derived Features
    bytes_ratio = orig_bytes / (resp_bytes + 1.0)
    pkt_rate = (orig_pkts + resp_pkts) / (duration + 1e-9)
    mean_pkt_size = orig_bytes / (orig_pkts + 1)
    mean_resp_pkt_size = resp_bytes / (resp_pkts + 1)

    # 3. Log transforms to handle heavy tailed distributions
    log_duration = math.log1p(duration)
    log_orig_bytes = math.log1p(orig_bytes)
    log_resp_bytes = math.log1p(resp_bytes)

    # 4. Connection state one-hot (6 states)
    state.key = conn_state if conn_state in CONN_STATES else "OTH"
    conn_state_vec = [1.0 if s == state_key else 0.0 for s in CONN_STATES ]

    # 5. Protocol binary flags
    is_tcp = 1.0 if proto == "tcp" else 0.0
    is_udp = 1.0 if proto == "udp" else 0.0

    # 6. Concatenate all features
    vec = np.array([
        duration,
        orig_bytes,
        resp_bytes,
        orig_pkts,
        resp_pkts,
        bytes_ratio,
        pkt_rate,
        mean_pkt_size,
        mean_resp_pkt_size,
        log_duration,
        log_orig_bytes,
        log_resp_bytes,
        *conn_state_vec,
        is_tcp,
        is_udp,
    ], dtype=np.float32)

    assert vec.shape == (20,), f"Expected shape {FEATURE_DIM}, got {vec.shape}"

    # 7. Replace NaN/Inf with 0
    vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)

    #return the feature of shape (FEATURE_DIM, )
    return vec

def build_feature_matrix(records: List[dict]) -> np.ndarray:
    """
    Vectorized version of build_feature_vector for batch processing.
    Used in the detection service
    
    Args:
        records: List of connection records
        
    Returns:
        np.ndarray: Feature matrix of shape (N, FEATURE_DIM)
    """
    return np.stack([build_feature_vector(record) for record in records])
