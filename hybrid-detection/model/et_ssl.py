"""
ET-SSL Model: Encoder + Projection Head

Architecture (configurable for hyperparameter search)
------------------------------------------------------
Encoder f_θ:
    n_hidden blocks of: Linear(in → hidden_dims[i]) → BatchNorm → ReLU → Dropout
    Final:              Linear(hidden_dims[-1] → embed_dim)   ← z_i (no activation)

Paper default (hidden_dims=(128, 256, 128), embed_dim=64):
    Linear(20 → 128) → BatchNorm → ReLU → Dropout
    Linear(128 → 256) → BatchNorm → ReLU → Dropout
    Linear(256 → 128) → BatchNorm → ReLU
    Linear(128 → 64)

Projection Head g_θ (training only, discarded at inference):
    Linear(embed_dim → embed_dim) → ReLU → Linear(embed_dim → proj_dim)

Usage
-----
Training  : model(x) → (z, h)  — use h for NT-Xent loss
Inference : model.encode(x) → z  — use z for anomaly scoring
"""

from __future__ import annotations

import torch
import torch.nn as nn

from config.constants import (
    FEATURE_DIM,
    EMBEDDING_DIM,
    PROJECTION_DIM,
)


class ETSSLEncoder(nn.Module):
    """
    Core encoder f_θ: maps x_i ∈ R^FEATURE_DIM → z_i ∈ R^embed_dim.

    Hidden layer widths and depth are configurable to support Optuna search.
    Each hidden block is: Linear → BatchNorm1d → ReLU → Dropout.
    The final linear layer has no activation (raw embeddings for L2 scoring).

    Args:
        hidden_dims: Tuple of hidden layer widths, e.g. (128, 256, 128).
                     Controls both depth and width of the encoder.
        embed_dim:   Output embedding dimension (z_i).
        dropout:     Dropout probability applied after each hidden block.
    """

    def __init__(
        self,
        hidden_dims: tuple[int, ...] = (128, 256, 128),
        embed_dim:   int   = EMBEDDING_DIM,
        dropout:     float = 0.3,
    ) -> None:
        super().__init__()

        layers: list[nn.Module] = []
        in_dim = FEATURE_DIM
        for i, h_dim in enumerate(hidden_dims):
            layers.append(nn.Linear(in_dim, h_dim))
            layers.append(nn.BatchNorm1d(h_dim))
            layers.append(nn.ReLU())
            # Dropout after every hidden block except the last
            if i < len(hidden_dims) - 1:
                layers.append(nn.Dropout(dropout))
            in_dim = h_dim

        # Final linear — no activation, no dropout (raw embeddings)
        layers.append(nn.Linear(in_dim, embed_dim))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch_size, FEATURE_DIM)
        Returns:
            z: (batch_size, embed_dim)
        """
        return self.net(x)


class ProjectionHead(nn.Module):
    """
    Small MLP projection head g_θ — used ONLY during contrastive training.

    Maps z_i → h_i for NT-Xent loss computation.
    Discarded after pre-training; use z_i directly for anomaly scoring.

    Args:
        embed_dim: Input dimension (must match ETSSLEncoder embed_dim).
        proj_dim:  Output projection dimension.
    """

    def __init__(
        self,
        embed_dim: int = EMBEDDING_DIM,
        proj_dim:  int = PROJECTION_DIM,
    ) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(embed_dim, embed_dim),
            nn.ReLU(),
            nn.Linear(embed_dim, proj_dim),
        )

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """
        Args:
            z: (batch_size, embed_dim)
        Returns:
            h: (batch_size, proj_dim)
        """
        return self.net(z)


class ETSSLModel(nn.Module):
    """
    Combined model for training: Encoder + Projection Head.

    At inference time, call .encode(x) to get embeddings z only.

    Args:
        hidden_dims: Hidden layer widths for the encoder, e.g. (128, 256, 128).
                     Tune this with Optuna to find optimal depth and width.
        embed_dim:   Embedding dimension.
        proj_dim:    Projection head output dimension.
        dropout:     Dropout probability.
    """

    def __init__(
        self,
        hidden_dims: tuple[int, ...] = (128, 256, 128),
        embed_dim:   int   = EMBEDDING_DIM,
        proj_dim:    int   = PROJECTION_DIM,
        dropout:     float = 0.3,
    ) -> None:
        super().__init__()
        self.encoder   = ETSSLEncoder(hidden_dims=hidden_dims, embed_dim=embed_dim, dropout=dropout)
        self.projector = ProjectionHead(embed_dim=embed_dim, proj_dim=proj_dim)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            x: (batch_size, FEATURE_DIM)
        Returns:
            z: embeddings (batch, embed_dim)   — for anomaly scoring
            h: projections (batch, proj_dim)   — for contrastive loss
        """
        z = self.encoder(x)
        h = self.projector(z)
        return z, h

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Inference-only shortcut — returns embeddings z without projection."""
        return self.encoder(x)