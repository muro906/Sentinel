"""
Column name mappings for different datasets raw file headers to the unified 20-feature names used throughout the pipeline
"""

# CIC-Darknet2020 column -> unified feature name
CIC_DARKNET2020_COLUMN_MAP = {
    "Flow Duration": "duration",
    "Total Fwd Packets": "orig_pkts",
    "Total Backward Packets": "resp_pkts",
    "Total Length of Fwd Packets": "orig_bytes",
    "Total Length of Bwd Packets": "resp_bytes",
    "Flow Packets/s": "pkt_rate",
    "Fwd Packet Length Mean": "mean_pkt_size",
    "Bwd Packet Length Mean": "mean_resp_pkt_size",
    "Protocol": "proto_raw", # 6=TCP, 17=UDP
    "Destination Port": "dst_port",
    "Label": "label_raw", # "BENIGN" or attack type
}

#UNSW-NB15 Column -> unified name
UNSW_MAP = {
    "dur": "duration",
    "sbytes": "orig_bytes",
    "dbytes": "resp_bytes",
    "spkts": "orig_pkts",
    "dpkts": "resp_pkts",
    "sload": "pkt_rate", # bits/sec (proxy)
    "smean": "mean_pkt_size",
    "dmean": "mean_resp_pkt_size",
    "proto": "proto_raw",
    "dport": "dst_port",
    "state": "conn_state_raw",
    "service": "service_raw",
    "label": "label_raw" # 0=normal 1=attack
    
}

# ISCX VPN-nonVPN column -> unified name
ISCX_MAP = {
    "duration": "duration",
    "total_fpackets": "orig_pkts",
    "total_bpackets": "resp_pkts",
    "total_fbytes": "orig_bytes",
    "total_bbytes": "resp_bytes",
    "rate": "pkt_rate",
    "mean": "mean_pkt_size",
    "Protocol": "proto_raw",
    "class1": "label_raw" # "VPN" or app category
}

# Unified binary label values for each dataset
LABEL_NORMAL = {
    'darknet': 'BENIGN',
    'unsw': 0,
    'iscx': 'BROWSING'
}
