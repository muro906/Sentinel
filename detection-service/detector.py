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

log = logging.getLogger("sentinel.detector")

MODEL_DIR   = Path(os.getenv("MODEL_DIR", "/models"))

# Sub-directories for each model inside MODEL_DIR.
MODEL_NAMES = ["darknet", "ids2018", "unsw"]

# ── Feature constants ─────────────────────────────────────────────────────────
CONN_STATES        = ["SF", "S0", "REJ", "RSTO", "RSTR", "OTH"]
CONTINUOUS_INDICES = list(range(12))


# ── Pure-numpy encoder (no torch required at inference) ───────────────────────

class _NumpyEncoder:
    """
    ET-SSL encoder implemented in pure numpy.

    Architecture: Linear → BN+ReLU → [Dropout (identity at inference)] → … → Linear
    Weights are loaded from encoder_weights.npz exported by prepare_model.py.

    State-dict key mapping (dots → double-underscore in npz):
        net__0__weight, net__0__bias          → Linear
        net__1__weight … net__1__running_var  → BatchNorm1d
        … (higher indices continue the pattern) …
        net__N__weight, net__N__bias          → Final Linear (no activation)
    """

    def __init__(self, ops: list) -> None:
        self._ops = ops   # list of ('linear', W, b) or ('bn_relu', w, b, mean, var)

    @classmethod
    def load(cls, npz_path: Path) -> "_NumpyEncoder":
        data = np.load(str(npz_path))
        # Restore original dot-notation keys
        sd = {k.replace('__', '.'): data[k] for k in data.files}

        # Group by layer index (e.g. "net.0.weight" → index 0)
        from collections import defaultdict
        layer_params: dict = defaultdict(dict)
        for key, arr in sd.items():
            parts = key.split('.')   # ['net', '0', 'weight']
            if len(parts) >= 3:
                layer_params[int(parts[1])][parts[2]] = arr.astype(np.float32)

        ops = []
        for idx in sorted(layer_params.keys()):
            p = layer_params[idx]
            if 'running_mean' in p:
                var  = p['running_var'].copy()
                mean = p['running_mean'].copy()
                corrupted = bool((var.max() > 100) or (np.abs(mean).max() > 100))
                if corrupted:
                    log.debug("BN layer %d: stats corrupted — falling back to per-batch norm", idx)
                ops.append(('bn_relu', p['weight'], p['bias'], mean, var, corrupted))
            elif 'weight' in p:
                ops.append(('linear', p['weight'], p['bias']))
        return cls(ops)

    def encode(self, x: np.ndarray) -> np.ndarray:
        """x: (N, feature_dim) float32 → (N, embed_dim) float32"""
        for op in self._ops:
            if op[0] == 'linear':
                x = x @ op[1].T + op[2]
            elif op[0] == 'bn_relu':
                _, w, b, mean, var, corrupted = op
                if corrupted:
                    # Per-batch layer normalisation fallback for corrupted stats.
                    # Normalise each feature across the batch; for single samples
                    # use feature-wise mean/std across the hidden dimension.
                    if x.shape[0] > 1:
                        mu  = x.mean(axis=0)
                        sig = x.std(axis=0) + 1e-5
                    else:
                        mu  = x.mean(axis=1, keepdims=True)
                        sig = x.std(axis=1, keepdims=True) + 1e-5
                    x = (x - mu) / sig * w + b
                else:
                    x = (x - mean) / np.sqrt(var + 1e-5) * w + b
                x = np.maximum(0, x)
        return x


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


# ── Single model ─────────────────────────────────────────────────────────────

class _SingleModel:
    """One trained ET-SSL model (encoder + scaler + centroid + threshold)."""

    def __init__(self, name: str, encoder, scaler, centroid, threshold):
        self.name      = name
        self.encoder   = encoder
        self.scaler    = scaler
        self.centroid  = centroid
        self.threshold = threshold
        self.degraded  = False   # set to True at load if BN stats are corrupted

    @classmethod
    def load_from(cls, model_dir: Path, name: str) -> "_SingleModel | None":
        meta_path = model_dir / "model_meta.json"
        if not meta_path.exists():
            return None
        with open(meta_path) as f:
            meta = json.load(f)

        npz_path = model_dir / "encoder_weights.npz"
        if not npz_path.exists():
            log.error("encoder_weights.npz missing in %s — re-run prepare_model.py", model_dir)
            return None

        encoder  = _NumpyEncoder.load(npz_path)
        scaler   = joblib.load(model_dir / "scaler.joblib")
        centroid = np.load(model_dir / "centroid.npy").astype(np.float32)
        threshold = float(meta.get("threshold") or 0.0)

        env_key = f"THRESHOLD_{name.upper()}"
        if os.getenv(env_key):
            threshold = float(os.getenv(env_key))
            log.info("Threshold for %s overridden by %s=%.4f", name, env_key, threshold)

        m = cls(name, encoder, scaler, centroid, threshold)
        probe = np.zeros(meta["feature_dim"], dtype=np.float32)
        probe_score = m.score(probe)

        # If probe_score is > 1000× the threshold the BN stats are too corrupted
        # to give meaningful anomaly scores — mark as degraded so the ensemble
        # can skip it rather than flagging every single flow.
        thr = threshold if threshold > 0 else 1.0
        # Exclude models where even a zero-vector probe is > 20x the threshold.
        # Probe scores this high indicate corrupted BN statistics — real traffic
        # will overflow and flag everything. Only the darknet model passes this.
        m.degraded = bool(probe_score > thr * 20)
        if m.degraded:
            log.warning("Model %-10s DEGRADED (probe_score=%.2e >> threshold=%.4f) "
                        "— excluded from ensemble until retrained",
                        name, probe_score, threshold)
        else:
            log.info("Loaded model %-10s | embed=%d threshold=%.4f  probe_score=%.4f",
                     name, meta["embed_dim"], threshold, probe_score)
        return m

    def score(self, x_raw: np.ndarray) -> float:
        x = x_raw.copy().reshape(1, -1).astype(np.float32)
        x[:, CONTINUOUS_INDICES] = self.scaler.transform(
            x[:, CONTINUOUS_INDICES]
        ).astype(np.float32)
        z = self.encoder.encode(x)[0]
        return float(((z - self.centroid) ** 2).sum())

    def score_batch(self, X_raw: np.ndarray) -> np.ndarray:
        X = X_raw.copy().astype(np.float32)
        X[:, CONTINUOUS_INDICES] = self.scaler.transform(
            X[:, CONTINUOUS_INDICES]
        ).astype(np.float32)
        Z = self.encoder.encode(X)
        return ((Z - self.centroid[None, :]) ** 2).sum(axis=1)


# ── Ensemble detector ─────────────────────────────────────────────────────────

class ETSSLDetector:
    """
    Ensemble of all available ET-SSL models.

    Each model specialises in one traffic distribution (darknet, ids2018, unsw).
    Cross-dataset AUC matrix showed each model fails on other distributions, so
    running all three and flagging on ANY model exceeding its threshold gives the
    best coverage across traffic types.

    Directory layout expected under MODEL_DIR:
        /models/darknet/   encoder_weights.pt  scaler.joblib  centroid.npy  model_meta.json
        /models/ids2018/   …
        /models/unsw/      …

    Falls back to MODEL_DIR/ directly for single-model deployments.

    Usage:
        detector = ETSSLDetector.load()
        result   = detector.detect(feature_dict)
    """

    def __init__(self, models: list[_SingleModel]) -> None:
        if not models:
            raise ValueError("No models loaded — run prepare_model.py first.")
        self._models = models
        log.info("Ensemble: %d model(s) — %s",
                 len(models), [m.name for m in models])

    @classmethod
    def load(cls) -> "ETSSLDetector":
        loaded = []

        # Try sub-directories first (multi-model)
        for name in MODEL_NAMES:
            sub = MODEL_DIR / name
            if sub.is_dir():
                m = _SingleModel.load_from(sub, name)
                if m:
                    loaded.append(m)

        # Fall back to MODEL_DIR itself (single-model, legacy layout)
        if not loaded:
            m = _SingleModel.load_from(MODEL_DIR, "default")
            if m:
                loaded.append(m)

        if not loaded:
            raise FileNotFoundError(
                f"No model_meta.json found under {MODEL_DIR}. "
                "Run: python detection-service/prepare_model.py"
            )
        active = [m for m in loaded if not m.degraded]
        if not active:
            log.error("All models degraded — using them anyway with caution")
            active = loaded
        elif len(active) < len(loaded):
            log.warning("%d/%d model(s) active (others degraded — need retraining)",
                        len(active), len(loaded))
        return cls(active)

    # ── Inference ─────────────────────────────────────────────────────────────

    def _ensemble_score(self, x_raw: np.ndarray) -> tuple[float, str, list[dict]]:
        """
        Score one feature vector with all models.
        Returns (max_normalised_confidence, triggering_model_name, per_model_votes).
        Flagged if ANY model exceeds its threshold (union rule — highest recall).
        """
        votes = []
        for m in self._models:
            raw   = m.score(x_raw)
            thr   = m.threshold if m.threshold > 0 else 1.0
            norm  = float(1 / (1 + np.exp(-(raw - thr) / (thr + 1e-9))))
            votes.append({
                "model_name": m.name,
                "score":      raw,
                "threshold":  thr,
                "is_anomaly": raw > thr,
                "confidence": norm,
            })

        triggered = [v for v in votes if v["is_anomaly"]]
        is_anomaly = bool(triggered)
        # Pick the most confident triggering model (or highest score if none triggered)
        if triggered:
            best = max(triggered, key=lambda v: v["confidence"])
        else:
            best = max(votes, key=lambda v: v["confidence"])

        return is_anomaly, best["model_name"], best["confidence"], votes

    def detect(self, record: dict) -> dict:
        x = _build_feature_vector(record)
        is_anomaly, model_name, confidence, votes = self._ensemble_score(x)
        return {
            "anomaly_score":  max(v["score"] for v in votes),
            "is_anomaly":     is_anomaly,
            "classification": "anomaly" if is_anomaly else "normal",
            "model_name":     model_name,
            "confidence":     confidence,
            "model_votes":    votes,
        }

    def detect_batch(self, records: list[dict]) -> list[dict]:
        if not records:
            return []
        X_raw = np.stack([_build_feature_vector(r) for r in records])
        results = []
        for i in range(len(X_raw)):
            is_anomaly, model_name, confidence, votes = self._ensemble_score(X_raw[i])
            results.append({
                "anomaly_score":  max(v["score"] for v in votes),
                "is_anomaly":     is_anomaly,
                "classification": "anomaly" if is_anomaly else "normal",
                "model_name":     model_name,
                "confidence":     confidence,
                "model_votes":    votes,
            })
        return results

    def update_centroid(self, normal_records: list[dict], alpha: float = 0.95) -> None:
        """EMA-update centroids in all models with new normal traffic observations."""
        if not normal_records:
            return
        X_raw = np.stack([_build_feature_vector(r) for r in normal_records])
        for m in self._models:
            X = X_raw.copy().astype(np.float32)
            X[:, CONTINUOUS_INDICES] = m.scaler.transform(
                X[:, CONTINUOUS_INDICES]
            ).astype(np.float32)
            Z = m.encoder.encode(X)
            new_mean   = Z.mean(axis=0).astype(np.float32)
            m.centroid = (alpha * m.centroid + (1 - alpha) * new_mean).astype(np.float32)
        log.debug("Centroids EMA-updated across %d models (alpha=%.2f)",
                  len(self._models), alpha)
