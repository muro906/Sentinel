"""
PyTorch Dataset for ET-SSL contrastive pre-training and optional supervised fine-tuning.

Modes
-----
Self-supervised (labels=None)  → __getitem__ returns (x_original, x_augmented)
Supervised (labels provided)   → __getitem__ returns (x_original, x_augmented, label)
"""

from __future__ import annotations

import numpy as np
import torch
from torch.utils.data import Dataset

from model.preprocessor import Augmenter


class TrafficDataset(Dataset):
    """
    Wraps a numpy feature matrix for use with a DataLoader.

    Args:
        X:        Scaled feature matrix, shape (N, FEATURE_DIM), float32.
        labels:   Optional binary label array, shape (N,). 0=normal, 1=anomaly.
        augmenter: Augmenter instance.  If None, a default Augmenter is created.
    """

    def __init__(
        self,
        X: np.ndarray,
        labels: np.ndarray | None = None,
        augmenter: Augmenter | None = None,
    ) -> None:
        self.X       = torch.from_numpy(X).float()
        self.labels  = torch.from_numpy(labels).long() if labels is not None else None
        self.augmenter = augmenter or Augmenter()

    # ── Dataset protocol ──────────────────────────────────────────────────────
    def __len__(self) -> int:
        return len(self.X)

    def __getitem__(self, idx: int):
        x_orig = self.X[idx]                             # (FEATURE_DIM,)
        # augmenter.augment() works on numpy; convert, augment, convert back
        x_aug  = torch.from_numpy(
            self.augmenter.augment(x_orig.numpy())
        ).float()                                        # (FEATURE_DIM,)

        if self.labels is not None:
            return x_orig, x_aug, self.labels[idx]
        return x_orig, x_aug