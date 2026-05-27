"""
Build a 20-dimensional feature vector from a raw Zeek conn.log record.

Feature layout (indices 0-19):
    0-11  continuous/derived features  → safe to augment
    12-17 conn_state one-hot (SF,S0,REJ,RSTO,RSTR,OTH)  → DO NOT augment
    18-19 proto binary flags (tcp, udp)                  → DO NOT augment

Called by:
    - notebooks : build numpy arrays from dataset CSV/parquet files
    - detection_service : build tensors from live Kafka messages
"""

from __future__ import annotations

import math
from typing import List

import numpy as np

from config.constants import FEATURE_DIM, CONTINUOUS_MASK, CATEGORICAL_MASK

# Connection states supported (matches FEATURE_NAMES order in constants.py)
CONN_STATES = ["SF", "S0", "REJ", "RSTO", "RSTR", "OTH"]


def build_feature_vector(record: dict) -> np.ndarray:
    """
    Build a float32 feature vector of shape (FEATURE_DIM,) from a conn.log record.

    Args:
        record: A dict with keys matching Zeek conn.log field names or unified
                names from the column maps.

    Returns:
        np.ndarray of shape (FEATURE_DIM,) with dtype float32.

    Steps:
        1. Extract scalar fields with safe defaults
        2. Derive ratio/rate features
        3. Apply log1p transforms
        4. Build one-hot vector for conn_state (6 classes)
        5. Build binary protocol flags
        6. Concatenate into final feature vector
        7. Replace NaN/Inf with 0
    """
    # 1. Raw field extraction
    duration    = float(record.get("duration", 0.0) or 0.0)
    orig_bytes  = float(record.get("orig_bytes",  0) or 0)
    resp_bytes  = float(record.get("resp_bytes",  0) or 0)
    orig_pkts   = float(record.get("orig_pkts",   0) or 0)
    resp_pkts   = float(record.get("resp_pkts",   0) or 0)
    proto       = str(record.get("proto", "") or "").lower()
    conn_state  = str(record.get("conn_state", "OTH") or "OTH").upper()
    dst_port    = int(record.get("dst_port", 0) or 0)  # noqa: F841 (available for future use)

    # 2. Derived features
    bytes_ratio       = orig_bytes / (resp_bytes + 1.0)
    pkt_rate          = (orig_pkts + resp_pkts) / (duration + 1e-9)
    mean_pkt_size     = orig_bytes / (orig_pkts + 1.0)
    mean_resp_pkt_size = resp_bytes / (resp_pkts + 1.0)

    # 3. Log transforms (handle heavy-tailed distributions)
    # Clamp to 0 before log1p — negative bytes/duration are physically impossible
    # and only arise as data artefacts in some CSVs (e.g. UNSW-NB15).
    log_duration   = math.log1p(max(duration,   0.0))
    log_orig_bytes = math.log1p(max(orig_bytes,  0.0))
    log_resp_bytes = math.log1p(max(resp_bytes,  0.0))

    # 4. Connection-state one-hot (6 classes: SF S0 REJ RSTO RSTR OTH)
    state_key = conn_state if conn_state in CONN_STATES else "OTH"
    conn_state_vec = [1.0 if s == state_key else 0.0 for s in CONN_STATES]

    # 5. Protocol binary flags
    is_tcp = 1.0 if proto == "tcp" else 0.0
    is_udp = 1.0 if proto == "udp" else 0.0

    # 6. Concatenate all features (order must match FEATURE_NAMES in constants.py)
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
        *conn_state_vec,   # indices 12-17
        is_tcp,            # index 18
        is_udp,            # index 19
    ], dtype=np.float32)

    assert vec.shape == (FEATURE_DIM,), \
        f"Expected shape ({FEATURE_DIM},), got {vec.shape}"

    # 7. Replace NaN/Inf with 0
    vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)
    return vec


def build_feature_matrix(records: List[dict]) -> np.ndarray:
    """
    Vectorized version of build_feature_vector for batch processing.
    Used in the detection service.

    Args:
        records: List of connection record dicts.

    Returns:
        np.ndarray: Feature matrix of shape (N, FEATURE_DIM), dtype float32.
    """
    return np.stack([build_feature_vector(r) for r in records], axis=0)
