"""
Anomaly Scorer for ET-SSL inference.

Maintains the normal traffic centroid μ_norm in embedding space and assigns
anomaly scores to incoming traffic flows.

Paper equations implemented here
---------------------------------
Anomaly score:     S(t_i) = ||z_i - μ_norm||²
Classification:    A(t_i) = 1 if S(t_i) > δ, else 0
Incremental EMA:   μ_norm^(t+1) = α * μ_norm^(t) + (1 - α) * mean(z_i for i ∈ N)
"""

from __future__ import annotations

import numpy as np

try:
    import torch
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False


class AnomalyScorer:
    """
    Computes anomaly scores from encoder embeddings.

    Workflow
    --------
    1. After pre-training, call .fit(normal_embeddings) to initialize μ_norm.
    2. At inference, call .score(z) to get squared-L2 distance to centroid.
    3. Call .is_anomaly(z, threshold) for a binary decision.
    4. Periodically call .update_centroid(new_normal_embeddings) to adapt.

    Args:
        alpha: EMA decay factor α for incremental centroid updates (paper: 0.95).
    """

    def __init__(self, alpha: float = 0.95) -> None:
        self.alpha    = alpha
        self._centroid: np.ndarray | None = None   # μ_norm, shape (EMBEDDING_DIM,)

    # ── Centroid management ───────────────────────────────────────────────────
    @property
    def centroid(self) -> np.ndarray:
        if self._centroid is None:
            raise RuntimeError("Centroid not initialized — call .fit() first.")
        return self._centroid

    def fit(self, normal_embeddings: np.ndarray) -> "AnomalyScorer":
        """
        Initialize centroid from a batch of normal-traffic embeddings.

        Args:
            normal_embeddings: (N, EMBEDDING_DIM) numpy array of embeddings
                               from the training split normal samples.
        """
        self._centroid = normal_embeddings.mean(axis=0).astype(np.float32)
        return self

    def update_centroid(self, new_normal_embeddings: np.ndarray) -> None:
        """
        Incremental EMA update for evolving traffic patterns.

        μ_norm^(t+1) = α * μ_norm^(t) + (1-α) * mean(new_z_i)

        Args:
            new_normal_embeddings: (N, EMBEDDING_DIM) numpy array of embeddings
                                   from recently observed normal traffic.
        """
        if self._centroid is None:
            self.fit(new_normal_embeddings)
            return
        new_mean       = new_normal_embeddings.mean(axis=0).astype(np.float32)
        self._centroid = (self.alpha * self._centroid
                          + (1.0 - self.alpha) * new_mean).astype(np.float32)

    # ── Scoring ───────────────────────────────────────────────────────────────
    def score(self, z: np.ndarray) -> np.ndarray:
        """
        Compute squared L2 distance from centroid: S(t_i) = ||z_i - μ_norm||²

        Args:
            z: (N, EMBEDDING_DIM) or (EMBEDDING_DIM,) — encoder embeddings.

        Returns:
            scores: (N,) float32 array of anomaly scores.
        """
        z = np.atleast_2d(z).astype(np.float32)
        diff = z - self._centroid[np.newaxis, :]   # (N, D)
        return (diff ** 2).sum(axis=1)              # (N,)

    def score_torch(self, z: "torch.Tensor") -> "torch.Tensor":
        """Torch version for in-training centroid diagnostics."""
        if not _TORCH_AVAILABLE:
            raise ImportError("torch is required for score_torch()")
        centroid = torch.tensor(self.centroid, device=z.device)
        return ((z - centroid.unsqueeze(0)) ** 2).sum(dim=1)

    def is_anomaly(self, z: np.ndarray, threshold: float) -> np.ndarray:
        """
        Binary anomaly classification.

        Args:
            z:         (N, EMBEDDING_DIM) or (EMBEDDING_DIM,)
            threshold: δ — anomaly score threshold.

        Returns:
            (N,) boolean array; True = anomaly.
        """
        return self.score(z) > threshold

    # ── Threshold calibration ─────────────────────────────────────────────────
    def calibrate_threshold(
        self,
        val_embeddings: np.ndarray,
        val_labels: np.ndarray,
        n_thresholds: int = 200,
    ) -> float:
        """
        Find the threshold δ that maximises F1-score on the validation set.

        Args:
            val_embeddings: (N, EMBEDDING_DIM)
            val_labels:     (N,) binary; 1 = anomaly
            n_thresholds:   number of candidate thresholds to try

        Returns:
            Best threshold (float).
        """
        from sklearn.metrics import f1_score

        scores    = self.score(val_embeddings)
        thresholds = np.linspace(scores.min(), scores.max(), n_thresholds)
        best_f1, best_thresh = 0.0, thresholds[0]

        for thresh in thresholds:
            preds = (scores > thresh).astype(int)
            f1    = f1_score(val_labels, preds, zero_division=0)
            if f1 > best_f1:
                best_f1, best_thresh = f1, thresh

        return float(best_thresh)

    # ── Persistence ───────────────────────────────────────────────────────────
    def save(self, path: str) -> None:
        """Save centroid to a .npy file."""
        if self._centroid is None:
            raise RuntimeError("Nothing to save — centroid is not initialized.")
        np.save(path, self._centroid)

    @classmethod
    def load(cls, path: str, alpha: float = 0.95) -> "AnomalyScorer":
        """Load centroid from a .npy file."""
        scorer = cls(alpha=alpha)
        scorer._centroid = np.load(path).astype(np.float32)
        return scorer
