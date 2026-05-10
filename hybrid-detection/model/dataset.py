"""
Pytorch dataset for contrastive pretraining and supervised fine-tuning
"""

import numpy as np
import torch
from torch.utils.data import Dataset
from model.prepocessor import Augmenter

class TrafficDataset(Dataset):
    """
    Wraps a numpy feature matrix for use with a Dataloader

    In self-supervised mode (labels=None)
    __getitem__ returns(x_original, x_augmented) - a positive pair

    In supervised mode (labels provided):
    __getitem__ returns (x_original, x_augmented, label)
    """

    def __init__(
        self,
        X: np.ndarray,
        labels: np.ndarray|None = None,
        augmenter: Augmenter| None = None
    ):
        """
        Args:
            X: Scaled feature matrix of shape (N, FEATURE_DIM)
            labels: optional binary labels array, shape(N,). 0=normal, 1=anomaly
            augmenter: Augmenter instance. If None, creates a default one
        """
        self.X = torch.from_numpy(X).float()
        self.labels = torch.from_numpy(labels).long() if labels is not None else None
        self.augmeter = augmenter or Augmenter()

    def __len__(self) -> int:
        return len(self.X)
    
    def __getitem__(self, idx: int):
        x_orig = self.X[idx]
        x_aug = torch.from_numpy(self.augmeter(x_orig.numpy()))
        if self.labels is not None:
            return x_orig, x_aug, self.labels[idx]
        return x_orig, x_aug