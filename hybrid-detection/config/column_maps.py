"""
Column name mappings for different datasets' raw file headers to the
unified 20-feature names used throughout the pipeline.

Datasets used:
    - CIC-Darknet2020  : CICFlowMeter-V3 output, Tor/VPN/DDoS attacks
    - UNSW-NB15        : Argus/Bro generated, 9 attack categories
    - CSE-CIC-IDS2018  : CICFlowMeter-V3 output, 7 modern attack scenarios

Notes on CICFlowMeter datasets (Darknet2020 & IDS2018):
    - Protocol is numeric (6=TCP, 17=UDP) — must be mapped to strings before
      feeding into build_feature_vector(). See CICFLOWMETER_PROTO_MAP.
    - conn_state is Zeek-specific and absent. Feature builder defaults to 'OTH'
      → one-hot [0,0,0,0,0,1] for all CICFlowMeter records. This is consistent
      across both datasets and reduces those 6 columns to constants, which is
      acceptable since the other 14 features still carry discriminative signal.
"""

# ── CIC-Darknet2020 column → unified feature name ────────────────────────────
CIC_DARKNET2020_COLUMN_MAP = {
    "Flow Duration":                 "duration",
    "Total Fwd Packets":             "orig_pkts",
    "Total Backward Packets":        "resp_pkts",
    "Total Length of Fwd Packets":   "orig_bytes",
    "Total Length of Bwd Packets":   "resp_bytes",
    "Flow Packets/s":                "pkt_rate",
    "Fwd Packet Length Mean":        "mean_pkt_size",
    "Bwd Packet Length Mean":        "mean_resp_pkt_size",
    "Protocol":                      "proto",   # numeric: 6=TCP, 17=UDP → use CICFLOWMETER_PROTO_MAP
    "Destination Port":              "dst_port",
    "Label":                         "label",   # "BENIGN" or attack type
}

# ── CSE-CIC-IDS2018 column → unified feature name ────────────────────────────
# Uses abbreviated CICFlowMeter-V3 headers (different from Darknet2020).
CIC_IDS2018_COLUMN_MAP = {
    "Flow Duration":    "duration",
    "Tot Fwd Pkts":     "orig_pkts",
    "Tot Bwd Pkts":     "resp_pkts",
    "TotLen Fwd Pkts":  "orig_bytes",
    "TotLen Bwd Pkts":  "resp_bytes",
    "Flow Pkts/s":      "pkt_rate",
    "Fwd Pkt Len Mean": "mean_pkt_size",
    "Bwd Pkt Len Mean": "mean_resp_pkt_size",
    "Protocol":         "proto",    # numeric: 6=TCP, 17=UDP → use CICFLOWMETER_PROTO_MAP
    "Dst Port":         "dst_port",
    "Label":            "label",    # "Benign" or attack type (note: not "BENIGN")
}

# Protocol number → string name for CICFlowMeter datasets.
# Apply after column renaming: df['proto'] = df['proto'].map(CICFLOWMETER_PROTO_MAP).fillna('other')
CICFLOWMETER_PROTO_MAP = {
    6:  "tcp",
    17: "udp",
    1:  "icmp",
    0:  "other",
}

# ── UNSW-NB15 column → unified name ──────────────────────────────────────────
UNSW_MAP = {
    "dur":     "duration",
    "sbytes":  "orig_bytes",
    "dbytes":  "resp_bytes",
    "spkts":   "orig_pkts",
    "dpkts":   "resp_pkts",
    "sload":   "pkt_rate",          # bits/sec (proxy)
    "smean":   "mean_pkt_size",
    "dmean":   "mean_resp_pkt_size",
    "proto":   "proto",             # string: "tcp", "udp", etc.
    "dport":   "dst_port",
    "state":   "conn_state",        # Argus state → Zeek-compatible conn_state
    "service": "service",
    "Label":   "label",             # 0=normal, 1=attack  (raw files use capital-L)
}

# ── Normal class per dataset ──────────────────────────────────────────────────
LABEL_NORMAL = {
    'darknet': 'BENIGN',
    'ids2018': 'Benign',    # note lowercase 'enign'
    'unsw':    0,
}

# ── Explicit anomaly class sets per dataset ───────────────────────────────────
# Threat model decisions documented here.
#
# darknet:
#   BENIGN = normal. All other classes anomalous, including:
#   - Tor / VPN   → encrypted tunneling for C2 / exfiltration
#   - DDoS / PortScan / Botnet / Infiltration → direct attacks
#   None means "everything != LABEL_NORMAL[dataset]"
#
# ids2018 (CSE-CIC-IDS2018):
#   "Benign" = normal. All other classes anomalous:
#   - DoS/DDoS attacks, Brute Force, Infiltration, Botnet, SQL Injection, XSS
#   None means "everything != LABEL_NORMAL[dataset]"
#
# unsw:
#   Binary — label=1 = attack. None means "everything != LABEL_NORMAL[dataset]"
LABEL_ANOMALY = {
    'darknet': None,   # all non-BENIGN classes
    'ids2018': None,   # all non-Benign classes
    'unsw':    None,   # all label=1 rows
}
