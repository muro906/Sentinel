"""
ET-SSL Detector — loads model artifacts and scores incoming feature dicts.

Artifacts expected in MODEL_DIR (set via env var):
    encoder_weights.pt   — ETSSLEncoder state dict
    scaler.joblib        — fitted RobustScaler
    centroid.npy         — normal traffic centroid μ_norm
    model_meta.json      — threshold, embed_dim, feature_dim, dropout

Scoring pipeline per connection:
    feature_dict → build_vector → scale → encode → L2 distance → anomaly score
"""

from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn as nn

log = logging.getLogger("sentinel.detector")

MODEL_DIR   = Path(os.getenv("MODEL_DIR", "/models"))
DEVICE      = torch.device("cpu")  # inference runs on CPU in production

# ── Feature constants ─────────────────────────────────────────────────────────
CONN_STATES        = ["SF", "S0", "REJ", "RSTO", "RSTR", "OTH"]
CONTINUOUS_INDICES = list(range(12))


# ── Encoder (mirrors et_ssl.py, standalone to avoid import path issues) ───────
class _ETSSLEncoder(nn.Module):
    """Dynamically builds encoder from hidden_dims tuple read from model_meta.json."""

    def __init__(
        self,
        feature_dim: int,
        embed_dim:   int,
        dropout:     float,
        hidden_dims: tuple[int, ...] = (128, 256, 128),
    ) -> None:
        super().__init__()
        layers: list[nn.Module] = []
        in_dim = feature_dim
        for i, h_dim in enumerate(hidden_dims):
            layers.append(nn.Linear(in_dim, h_dim))
            layers.append(nn.BatchNorm1d(h_dim))
            layers.append(nn.ReLU())
            if i < len(hidden_dims) - 1:
                layers.append(nn.Dropout(dropout))
            in_dim = h_dim
        layers.append(nn.Linear(in_dim, embed_dim))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


# ── Feature builder (self-contained copy) ────────────────────────────────────
def _build_feature_vector(record: dict) -> np.ndarray:
    dur   = float(record.get("duration", 0) or 0)
    ob    = float(record.get("orig_bytes", 0) or 0)
    rb    = float(record.get("resp_bytes", 0) or 0)
    op    = float(record.get("orig_pkts", 0) or 0)
    rp    = float(record.get("resp_pkts", 0) or 0)
    proto = str(record.get("proto", "") or "").lower()
    cs    = str(record.get("conn_state", "OTH") or "OTH").upper()
    cs    = cs if cs in CONN_STATES else "OTH"

    feat = [
        dur, ob, rb, op, rp,
        ob / (rb + 1.0),
        (op + rp) / (dur + 1e-9),
        ob / (op + 1.0),
        rb / (rp + 1.0),
        math.log1p(dur),
        math.log1p(ob),
        math.log1p(rb),
        *[1.0 if s == cs else 0.0 for s in CONN_STATES],
        1.0 if proto == "tcp" else 0.0,
        1.0 if proto == "udp" else 0.0,
    ]
    vec = np.array(feat, dtype=np.float32)
    return np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)


# ── Main Detector class ───────────────────────────────────────────────────────
class ETSSLDetector:
    """
    Loads ET-SSL artifacts and scores network feature dicts.

    Usage:
        detector = ETSSLDetector.load()
        result   = detector.detect(feature_dict)
    """

    def __init__(
        self,
        encoder:   _ETSSLEncoder,
        scaler:    object,
        centroid:  np.ndarray,
        threshold: float,
        feature_dim: int,
    ) -> None:
        self._encoder   = encoder
        self._scaler    = scaler
        self._centroid  = centroid
        self._threshold = threshold
        self._feature_dim = feature_dim

    @classmethod
    def load(cls) -> "ETSSLDetector":
        """Load all artifacts from MODEL_DIR."""
        meta_path = MODEL_DIR / "model_meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(
                f"model_meta.json not found in {MODEL_DIR}. "
                "Copy production artifacts from Colab export."
            )

        with open(meta_path) as f:
            meta = json.load(f)

        feature_dim = meta["feature_dim"]
        embed_dim   = meta["embed_dim"]
        dropout     = meta.get("dropout", 0.3)
        threshold   = meta["threshold"]
        hidden_dims = tuple(meta.get("hidden_dims", [128, 256, 128]))

        encoder = _ETSSLEncoder(
            feature_dim, embed_dim, dropout, hidden_dims=hidden_dims
        ).to(DEVICE)
        state   = torch.load(MODEL_DIR / "encoder_weights.pt", map_location=DEVICE)
        encoder.load_state_dict(state)
        encoder.eval()

        scaler   = joblib.load(MODEL_DIR / "scaler.joblib")
        centroid = np.load(MODEL_DIR / "centroid.npy").astype(np.float32)

        log.info(
            "ET-SSL detector loaded | embed_dim=%d threshold=%.4f",
            embed_dim, threshold,
        )
        return cls(encoder, scaler, centroid, threshold, feature_dim)

    # ── Inference ─────────────────────────────────────────────────────────────
    def score(self, record: dict) -> float:
        """Return anomaly score S(t) = ||z - μ_norm||² for one record."""
        x = _build_feature_vector(record)
        # Scale only continuous columns
        x[CONTINUOUS_INDICES] = self._scaler.transform(
            x[CONTINUOUS_INDICES].reshape(1, -1)
        ).flatten().astype(np.float32)

        with torch.no_grad():
            z      = self._encoder(torch.from_numpy(x).unsqueeze(0).to(DEVICE))
            z_np   = z.cpu().numpy()[0]
        diff   = z_np - self._centroid
        return float((diff ** 2).sum())

    def detect(self, record: dict) -> dict:
        """
        Full detection result for one feature record.

        Returns dict with:
            anomaly_score  – float [0, ∞)
            is_anomaly     – bool
            classification – str  ('anomaly' | 'normal')
            model_name     – 'et_ssl'
            confidence     – float [0, 1]  (sigmoid of normalised score)
        """
        raw_score  = self.score(record)
        is_anomaly = raw_score > self._threshold
        # Normalise score to [0,1] via sigmoid around threshold
        normalised = float(1 / (1 + np.exp(-(raw_score - self._threshold) / (self._threshold + 1e-9))))
        return {
            "anomaly_score":  raw_score,
            "is_anomaly":     is_anomaly,
            "classification": "anomaly" if is_anomaly else "normal",
            "model_name":     "et_ssl",
            "confidence":     normalised,
        }

    def detect_batch(self, records: list[dict]) -> list[dict]:
        """Score a list of records efficiently."""
        if not records:
            return []
        # Build matrix
        X = np.stack([_build_feature_vector(r) for r in records])
        X[:, CONTINUOUS_INDICES] = self._scaler.transform(
            X[:, CONTINUOUS_INDICES]
        ).astype(np.float32)

        with torch.no_grad():
            Z = self._encoder(torch.from_numpy(X).to(DEVICE)).cpu().numpy()

        diffs  = Z - self._centroid[None, :]
        scores = (diffs ** 2).sum(axis=1)

        results = []
        for score in scores:
            is_anom  = bool(score > self._threshold)
            norm     = float(1 / (1 + np.exp(-(score - self._threshold) / (self._threshold + 1e-9))))
            results.append({
                "anomaly_score":  float(score),
                "is_anomaly":     is_anom,
                "classification": "anomaly" if is_anom else "normal",
                "model_name":     "et_ssl",
                "confidence":     norm,
            })
        return results

    def update_centroid(self, normal_records: list[dict], alpha: float = 0.95) -> None:
        """EMA-update centroid with new normal traffic observations."""
        if not normal_records:
            return
        X = np.stack([_build_feature_vector(r) for r in normal_records])
        X[:, CONTINUOUS_INDICES] = self._scaler.transform(
            X[:, CONTINUOUS_INDICES]
        ).astype(np.float32)
        with torch.no_grad():
            Z = self._encoder(torch.from_numpy(X).to(DEVICE)).cpu().numpy()
        new_mean       = Z.mean(axis=0).astype(np.float32)
        self._centroid = (alpha * self._centroid + (1 - alpha) * new_mean).astype(np.float32)
        log.debug("Centroid updated via EMA (alpha=%.2f)", alpha)
