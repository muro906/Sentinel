"""
ET-SSL Model: Encoder + Projection Head

Architecture:
    Encoder:    Linear(20->128)->BN -> ReLU -> Dropout
                Linear(128 -> 256) -> BN -> ReLU -> Dropout
                Linear(256 -> 128) -> BN ->ReLU 
                Linear(128 -> 64) <- embedding z_i
    
    Projection Head: Linear(64 -> 64) -> ReLU -> Linear(64 -> 32) <- h_i
"""
import torch
import torch.nn as nn
from config.constants import (
    FEATURE_DIM, ENCODER_HIDDEN_1,ENCODER_HIDDEN_2, ENCODER_HIDDEN_3,EMBEDDING_DIM,
    PROJECTION_DIM
)

class ETSSLEncoder(nn.Module):
    """
    This core encoder maps the input feature vector to a 64 dim vector
    Consider it a function f_theta that maps x_i in R^20 to z_i in R^64

    The module is kept after training and used for inference
    """
    def __init__(self, dropout: float=0.3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(FEATURE_DIM, ENCODER_HIDDEN_1),
            nn.BatchNorm1d(ENCODER_HIDDEN_1),
            nn.ReLU(),
            nn.Dropout(dropout),

            nn.Linear(ENCODER_HIDDEN_1, ENCODER_HIDDEN_2),
            nn.BatchNorm1d(ENCODER_HIDDEN_2),
            nn.ReLU(),
            nn.Dropout(dropout),

            nn.Linear(ENCODER_HIDDEN_2, ENCODER_HIDDEN_3),
            nn.BatchNorm1d(ENCODER_HIDDEN_3),
            nn.ReLU(),

            nn.Linear(ENCODER_HIDDEN_3, EMBEDDING_DIM)
            # No activations in final layer as we use the raw embeddings for distance scoring
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch_size, FEATURE_DIM)
        Returns:
            z: (batch_size, EMBEDDING_DIM)
        """
        return self.net(x)

class ProjectionHead(nn.Module):
    """
    Small MLP projection head ONLY used during contrastive Learning
    Maps z_i to h_i for the NT-Xent loss computation
    Discards this after training; use z_i directly for anomaly scoring
    
    """
    def __init__(self):
        super().__init__()
        self.net = nn. Sequential(
            nn.Linear(EMBEDDING_DIM, EMBEDDING_DIM),
            nn.ReLU(),
            nn.Linear(EMBEDDING_DIM,PROJECTION_DIM)
        )
    
    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """
        Args:
            z: (batch_size, EMBEDDING_DIM)
        Returns:
            h: (batch_size, PROJECTION_DIM)
        """
        return self.net(z)

class ETSSLModel(nn.Module):
    """
    combined model for training: Encoder + Projection Head
    Use encoder.forward() alone at inference time.
    """
    def __init__(self, dropout: float=0.3):
        super().__init__()
        self.encoder = ETSSLEncoder(dropout=dropout)
        self.projector = ProjectionHead()

    def forward(self, x: torch.Tensor) -> tuple(torch.Tensor, torch.Tensor):
        """
        Returns:
            z: embeddings (batch, EMBEDDING_DIM) - for anomaly scoring
            h: projections (batch, PROJECTION_DIM) - for contrastive loss
        """
        z = self.encoder(x)
        h = self.projector(z)
        return z,h
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Inference-only shortcut: return embeddings z only"""
        return self.encoder(x)

        