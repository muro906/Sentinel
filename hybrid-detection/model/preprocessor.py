"""
Preprocessing for the ET-SSL pipeline.

Provides:
    TrafficScaler  – RobustScaler wrapper that preserves one-hot columns
    Augmenter      – Stochastic augmentation that NEVER corrupts categorical features
"""

from __future__ import annotations

import numpy as np
import joblib
from sklearn.preprocessing import RobustScaler

from config.constants import (
    FEATURE_DIM,
    CONTINUOUS_MASK,
    CATEGORICAL_MASK,
    CONTINUOUS_INDICES,
)


class TrafficScaler:
    """
    Thin wrapper around sklearn RobustScaler.

    IMPORTANT: The scaler is fitted and applied ONLY to continuous columns
    (indices 0-11).  The one-hot / binary columns (indices 12-19) pass through
    unchanged — they are already in {0, 1} and must not be rescaled.
    """

    def __init__(self) -> None:
        self._scaler = RobustScaler()

    # ── Fit ───────────────────────────────────────────────────────────────────
    def fit(self, X: np.ndarray) -> "TrafficScaler":
        """
        Fit the scaler on training data X of shape (N, FEATURE_DIM).
        Only the continuous columns are used for fitting.
        """
        self._scaler.fit(X[:, CONTINUOUS_INDICES])
        return self

    # ── Transform ─────────────────────────────────────────────────────────────
    def transform(self, X: np.ndarray) -> np.ndarray:
        """
        Scale X and return a float32 array of the same shape.
        One-hot / binary columns are copied as-is.
        """
        X_out = X.copy().astype(np.float32)
        X_out[:, CONTINUOUS_INDICES] = self._scaler.transform(
            X[:, CONTINUOUS_INDICES]
        ).astype(np.float32)
        return X_out

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)

    # ── Persistence ───────────────────────────────────────────────────────────
    def save(self, path: str) -> None:
        """Persist the fitted scaler to disk."""
        joblib.dump(self._scaler, path)

    @classmethod
    def load(cls, path: str) -> "TrafficScaler":
        """Load a previously fitted scaler from disk."""
        instance = cls()
        instance._scaler = joblib.load(path)
        return instance


class Augmenter:
    """
    Stochastic data augmentation for self-supervised contrastive learning.

    Given a sample x_i, returns x_i_aug — a perturbed positive view of x_i
    that the encoder must map close to x_i in embedding space.

    CRITICAL CONTRACT
    -----------------
    One-hot and binary columns (indices 12-19) are NEVER modified.
    Augmentations operate exclusively on continuous columns (indices 0-11).

    Available augmentations
    -----------------------
    gaussian_noise  : add N(0, σ) to continuous features
    feature_dropout : zero out up to `dropout_max` continuous features
    scale_jitter    : multiply continuous features by U(lo, hi)
    """

    def __init__(
        self,
        noise_std: float = 0.05,
        dropout_max: int = 3,
        jitter_range: tuple[float, float] = (0.9, 1.1),
    ) -> None:
        self.noise_std    = noise_std
        self.dropout_max  = dropout_max
        self.jitter_range = jitter_range

    # ── Public API ────────────────────────────────────────────────────────────
    def augment(self, x: np.ndarray) -> np.ndarray:
        """
        Apply 1 or 2 randomly chosen augmentations to a single feature vector.

        Args:
            x: 1-D float32 array of shape (FEATURE_DIM,)

        Returns:
            Augmented copy of x (original is not modified).
        """
        x_aug   = x.copy().astype(np.float32)
        n_augs  = np.random.randint(1, 3)   # apply 1 or 2 augmentations
        choices = np.random.choice(
            ["noise", "dropout", "jitter"], size=n_augs, replace=False
        )
        for aug in choices:
            if aug == "noise":
                x_aug = self._gaussian_noise(x_aug)
            elif aug == "dropout":
                x_aug = self._feature_dropout(x_aug)
            elif aug == "jitter":
                x_aug = self._scale_jitter(x_aug)

        # Sanity-check: categorical columns must be untouched
        assert (x_aug[CATEGORICAL_MASK] == x[CATEGORICAL_MASK]).all(), \
            "BUG: augmentation corrupted one-hot/binary features!"

        return x_aug.astype(np.float32)

    def augment_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Apply augmentation to a batch of samples.

        Args:
            X: float32 array of shape (N, FEATURE_DIM)

        Returns:
            np.ndarray: augmented array of shape (N, FEATURE_DIM)
        """
        return np.stack([self.augment(x) for x in X], axis=0)

    # ── Private augmentation methods ──────────────────────────────────────────
    def _gaussian_noise(self, x: np.ndarray) -> np.ndarray:
        """Add Gaussian noise to continuous columns only."""
        noise = np.zeros_like(x)
        noise[CONTINUOUS_MASK] = np.random.normal(
            0.0, self.noise_std, size=int(CONTINUOUS_MASK.sum())
        ).astype(np.float32)
        return x + noise

    def _feature_dropout(self, x: np.ndarray) -> np.ndarray:
        """Zero out a random subset of continuous columns."""
        n   = np.random.randint(1, self.dropout_max + 1)
        idx = np.random.choice(CONTINUOUS_INDICES, size=n, replace=False)
        x_out = x.copy()
        x_out[idx] = 0.0
        return x_out

    def _scale_jitter(self, x: np.ndarray) -> np.ndarray:
        """Multiply continuous columns by a uniform scale factor."""
        lo, hi = self.jitter_range
        scale = np.ones(FEATURE_DIM, dtype=np.float32)
        scale[CONTINUOUS_MASK] = np.random.uniform(
            lo, hi, size=int(CONTINUOUS_MASK.sum())
        ).astype(np.float32)
        return x * scale