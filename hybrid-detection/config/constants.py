"""
Shared constants used across feature extraction, rules and detection service.

Feature vector layout (20-dim):
    [0]  duration
    [1]  orig_bytes
    [2]  resp_bytes
    [3]  orig_pkts
    [4]  resp_pkts
    [5]  bytes_ratio
    [6]  pkt_rate
    [7]  mean_pkt_size
    [8]  mean_resp_pkt_size
    [9]  log_duration
    [10] log_orig_bytes
    [11] log_resp_bytes
    [12] conn_state_SF       ← one-hot start
    [13] conn_state_S0
    [14] conn_state_REJ
    [15] conn_state_RSTO
    [16] conn_state_RSTR
    [17] conn_state_OTH
    [18] proto_tcp           ← binary flags
    [19] proto_udp
"""
import numpy as np

# The 20 feature names in order - must match build_feature_vector() output
FEATURE_NAMES = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "bytes_ratio",
    "pkt_rate",
    "mean_pkt_size",
    "mean_resp_pkt_size",
    "log_duration",
    "log_orig_bytes",
    "log_resp_bytes",
    "conn_state_SF",
    "conn_state_S0",       # ← comma was missing here in original, causing DIM=19
    "conn_state_REJ",
    "conn_state_RSTO",
    "conn_state_RSTR",
    "conn_state_OTH",
    "proto_tcp",
    "proto_udp",
]

FEATURE_DIM = len(FEATURE_NAMES)  # 20

# ── One-hot / categorical protection ─────────────────────────────────────────
# Indices of features that are categorical (one-hot conn_state + binary proto).
# Augmentation methods MUST NOT modify these columns.
ONE_HOT_START_IDX = 12   # first categorical index
CATEGORICAL_INDICES = list(range(12, 20))   # [12,13,14,15,16,17,18,19]
CONTINUOUS_INDICES  = list(range(0, 12))    # [0..11]

# Boolean masks (shape FEATURE_DIM) for masked augmentation
CONTINUOUS_MASK  = np.array(
    [True] * 12 + [False] * 8, dtype=bool
)   # True where augmentation is safe
CATEGORICAL_MASK = ~CONTINUOUS_MASK  # True where augmentation must be skipped

# ── Architecture ──────────────────────────────────────────────────────────────
# Default dimensions (paper). Hidden layer widths are now configurable via
# the hidden_dims tuple in ETSSLModel — Optuna tunes both depth and width.
EMBEDDING_DIM    = 64   # z_i dimension (encoder output)
PROJECTION_DIM   = 32   # h_i dimension (projection head, training only)

# ── Training hyperparameters (paper values) ───────────────────────────────────
BATCH_SIZE        = 256    # paper: 256; use 128 if GPU VRAM is tight
LEARNING_RATE     = 1e-3   # paper: 0.001
LR_DECAY_FACTOR   = 0.95   # paper: 0.95 decay every 10 epochs
LR_DECAY_EPOCHS   = 10
NUM_EPOCHS        = 100
TEMPERATURE_TAU   = 0.1    # τ  – contrastive loss temperature
GAMMA             = 0.5    # γ  – anomaly loss weight
ALPHA_EMA         = 0.95   # α  – incremental centroid decay factor

# ── Data splits ───────────────────────────────────────────────────────────────
TRAIN_RATIO = 0.70
VAL_RATIO   = 0.15
TEST_RATIO  = 0.15