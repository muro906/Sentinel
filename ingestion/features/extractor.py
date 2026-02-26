"""
Feature Extractor – CESSNET-like feature extraction from Zeek logs.

Parses conn.log (primary), ssl.log, dns.log (optional enrichment)
and produces structured feature vectors per connection.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pandas as pd
import numpy as np


# ── Zeek TSV helpers ──────────────────────────────────────────────────────────

def _read_zeek_log(path: Path) -> pd.DataFrame:
    """Read a Zeek ASCII/JSON log into a DataFrame."""
    if not path.exists():
        return pd.DataFrame()
    try:
        # JSON-formatted logs (LogAscii::use_json=T)
        records = []
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return pd.DataFrame(records) if records else pd.DataFrame()
    except Exception as exc:
        print(f"[extractor] WARN reading {path}: {exc}")
        return pd.DataFrame()


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        v = float(val)
        return v if np.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return default


# ── Connection-state one-hot encoding ─────────────────────────────────────────

CONN_STATES = [
    "S0", "S1", "S2", "S3", "SF",
    "REJ", "RSTO", "RSTR", "RSTOS0",
    "RSTRH", "SH", "SHR", "OTH",
]

def _conn_state_onehot(state: str) -> dict[str, int]:
    return {f"conn_state_{s}": int(state == s) for s in CONN_STATES}


# ── Protocol encoding ──────────────────────────────────────────────────────────

PROTO_MAP = {"tcp": 0, "udp": 1, "icmp": 2}

def _proto_encode(proto: str) -> int:
    return PROTO_MAP.get(str(proto).lower(), 3)


# ── Main extraction ────────────────────────────────────────────────────────────

def extract_features(log_dir: Path) -> list[dict]:
    """
    Extract CESSNET-like feature vectors from a Zeek log directory.

    Returns a list of dicts, one per connection record in conn.log.
    """
    conn_df  = _read_zeek_log(log_dir / "conn.log")
    ssl_df   = _read_zeek_log(log_dir / "ssl.log")
    dns_df   = _read_zeek_log(log_dir / "dns.log")

    if conn_df.empty:
        return []

    # Optional SSL enrichment
    ssl_map: dict[str, dict] = {}
    if not ssl_df.empty and "uid" in ssl_df.columns:
        for _, row in ssl_df.iterrows():
            ssl_map[str(row.get("uid", ""))] = {
                "ssl_version": str(row.get("version", "")),
                "ssl_cipher":  str(row.get("cipher", "")),
                "ssl_resumed": int(bool(row.get("resumed", False))),
            }

    # Optional DNS enrichment
    dns_map: dict[str, dict] = {}
    if not dns_df.empty and "uid" in dns_df.columns:
        for _, row in dns_df.iterrows():
            dns_map[str(row.get("uid", ""))] = {
                "dns_query":  str(row.get("query", "")),
                "dns_qtype":  _safe_int(row.get("qtype", 0)),
                "dns_rcode":  _safe_int(row.get("rcode", -1)),
                "dns_answers": _safe_int(row.get("answers", 0)
                                         if not isinstance(row.get("answers"), list)
                                         else len(row.get("answers", []))),
            }

    vectors: list[dict] = []

    for _, row in conn_df.iterrows():
        uid   = str(row.get("uid", ""))
        ts    = str(row.get("ts", ""))
        proto = str(row.get("proto", ""))

        # Core CESSNET-like numeric features
        features: dict[str, Any] = {
            # Identifiers / metadata
            "uid":      uid,
            "ts":       ts,
            "src_ip":   str(row.get("id.orig_h", "")),
            "src_port": _safe_int(row.get("id.orig_p", 0)),
            "dst_ip":   str(row.get("id.resp_h", "")),
            "dst_port": _safe_int(row.get("id.resp_p", 0)),
            "proto":    proto,
            "proto_enc": _proto_encode(proto),
            "service":  str(row.get("service", "")),

            # Volume / duration
            "duration":      _safe_float(row.get("duration", 0)),
            "orig_bytes":    _safe_int(row.get("orig_bytes", 0)),
            "resp_bytes":    _safe_int(row.get("resp_bytes", 0)),
            "orig_pkts":     _safe_int(row.get("orig_pkts", 0)),
            "resp_pkts":     _safe_int(row.get("resp_pkts", 0)),
            "orig_ip_bytes": _safe_int(row.get("orig_ip_bytes", 0)),
            "resp_ip_bytes": _safe_int(row.get("resp_ip_bytes", 0)),
            "missed_bytes":  _safe_int(row.get("missed_bytes", 0)),

            # Derived ratios (CESSNET style)
            "bytes_ratio": (
                _safe_int(row.get("orig_bytes", 0)) /
                max(_safe_int(row.get("resp_bytes", 1)), 1)
            ),
            "pkts_ratio": (
                _safe_int(row.get("orig_pkts", 0)) /
                max(_safe_int(row.get("resp_pkts", 1)), 1)
            ),
            "avg_pkt_size_orig": (
                _safe_int(row.get("orig_bytes", 0)) /
                max(_safe_int(row.get("orig_pkts", 1)), 1)
            ),
            "avg_pkt_size_resp": (
                _safe_int(row.get("resp_bytes", 0)) /
                max(_safe_int(row.get("resp_pkts", 1)), 1)
            ),

            # Connection state one-hot
            **_conn_state_onehot(str(row.get("conn_state", "OTH"))),

            # History flags (present / absent)
            "history": str(row.get("history", "")),
        }

        # SSL enrichment
        ssl_info = ssl_map.get(uid, {})
        features.update({
            "ssl_version":  ssl_info.get("ssl_version", ""),
            "ssl_cipher":   ssl_info.get("ssl_cipher", ""),
            "ssl_resumed":  ssl_info.get("ssl_resumed", 0),
            "is_encrypted": int(bool(ssl_info)),
        })

        # DNS enrichment
        dns_info = dns_map.get(uid, {})
        features.update({
            "dns_query":   dns_info.get("dns_query", ""),
            "dns_qtype":   dns_info.get("dns_qtype", -1),
            "dns_rcode":   dns_info.get("dns_rcode", -1),
            "dns_answers": dns_info.get("dns_answers", 0),
            "is_dns":      int(bool(dns_info)),
        })

        vectors.append(features)

    return vectors
