"""
Shared constants used across feature extraction, rules and detection service

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
    "conn_state_S0"
    "conn_state_REJ",
    "conn_state_RSTO",
    "conn_state_RSTR",
    "conn_state_OTH",
    "proto_tcp",
    "proto_udp",
]

FEATURE_DIM = len(FEATURE_NAMES) # 20

# Well-known ports used by rule engine
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432,6379, 8080, 8443,8888]

# ET-SSL model dimensions
ENCODER_HIDDEN_1 = 128
ENCODER_HIDDEN_2 = 256
ENCODER_HIDDEN_3 = 128
EMBEDDING_DIM = 64
PROJECTION_DIM = 32

# TRAINING HYPERPARAMETERS
BATCH_SIZE = 128 # For colab
LEARNING_RATE = 1e-3
LR_DECAY_FACTOR = 0.95 # Learning rate decay factor
LR_DECAY_EPOCHS = 10 # Learning rate decay every N epochs
NUM_EPOCHS = 100
TEMPERATURE_TAU = 0.1 # Temperature for contrastive loss
GAMMA = 0.5 # Weight for anomaly detection loss
ALPHA_EMA = 0.95 # incremental centroid decay factor

# Train/val/test split ratios
TRAIN_RATIO = 0.7
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Detection
SCORE_NORMALISE_PERCENTILE = 0.95 # Clip scores above this percentile
ENSEMBLE_WEIGHTS = {
    "et_ssl": 0.5,
    "random_forest": 0.25,
    "autoencoder": 0.15,
    "rule_engine": 0.10
}

ENSEMBLE_THRESHOLD = 0.5 # Threshold for ensemble prediction