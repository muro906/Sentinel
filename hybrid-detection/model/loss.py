"""
Loss functions for ET-SSL contrastive pre-training.

Implements the paper's total loss:
    L_total = L_contrastive + γ * L_anomaly

Components
----------
NTXentLoss   – NT-Xent (Normalized Temperature-scaled Cross-Entropy) loss
               from SimCLR; matches paper Eq. 5.
AnomalyLoss  – Anomaly separation term; matches paper Eq. 3.
CombinedLoss – Wraps both with configurable γ.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


class NTXentLoss(nn.Module):
    """
    NT-Xent (Normalized Temperature-scaled Cross-Entropy) loss.

    Given a batch of N original embeddings z and N augmented embeddings z+,
    the (z_i, z+_i) pair is the positive pair; all other 2(N-1) embeddings in
    the batch are treated as negatives for sample i.

    Paper formula:
        L = -(1/2N) Σ_{i=1}^{2N}  log[
                exp(sim(z_i, z+_i) / τ)
              / Σ_{j≠i} exp(sim(z_i, z_j) / τ)
            ]

    Args:
        temperature: τ — temperature parameter (paper: 0.1).
    """

    def __init__(self, temperature: float = 0.1) -> None:
        super().__init__()
        self.temperature = temperature

    def forward(
        self,
        h: torch.Tensor,
        h_aug: torch.Tensor,
    ) -> torch.Tensor:
        """
        Compute NT-Xent loss.

        Args:
            h:     (N, D) — projected embeddings of original samples.
            h_aug: (N, D) — projected embeddings of augmented samples.

        Returns:
            Scalar loss tensor.
        """
        N   = h.shape[0]
        device = h.device

        # L2-normalise so cosine_similarity = dot product
        h     = F.normalize(h,     dim=1)   # (N, D)
        h_aug = F.normalize(h_aug, dim=1)   # (N, D)

        # Concatenate to form 2N embeddings: [z_1, z_2, ..., z_N, z+_1, ..., z+_N]
        representations = torch.cat([h, h_aug], dim=0)   # (2N, D)

        # Full 2N×2N similarity matrix (divided by τ)
        sim_matrix = torch.matmul(representations, representations.T) / self.temperature
        # (2N, 2N)

        # Mask out self-similarities (diagonal)
        mask = (~torch.eye(2 * N, dtype=torch.bool, device=device))

        # Positive pair indices:
        #   for i in [0, N):   positive is i + N
        #   for i in [N, 2N):  positive is i - N
        pos_idx = torch.cat([
            torch.arange(N, 2 * N, device=device),
            torch.arange(0, N,     device=device),
        ])  # (2N,)

        # log-numerator: sim(z_i, z+_i) / τ  [i.e. log(exp(sim/τ)) = sim/τ]
        log_num = sim_matrix[torch.arange(2 * N, device=device), pos_idx]  # (2N,)

        # log-denominator: log( Σ_{j≠i} exp(sim(z_i, z_j) / τ) )  via logsumexp for stability
        log_den = sim_matrix.masked_select(mask).view(2 * N, -1).logsumexp(dim=1)  # (2N,)

        # ℓ(i) = -(log_num - log_den) = -log[ exp(sim/τ) / Σ exp(sim/τ) ]
        loss = -(log_num - log_den).mean()
        return loss


class AnomalyLoss(nn.Module):
    """
    Anomaly separation loss.

    Pushes anomalous traffic embeddings away from the normal centroid z_0.

    Paper formula:
        L_anomaly = Σ_i  II(A(t_i)) * ||z_i - z_0||²

    where II(A(t_i)) is the indicator function — 1 if sample i is anomalous,
    0 otherwise.

    This term is only meaningful during the supervised fine-tuning phase
    when labels are available.  During pure self-supervised pre-training,
    anomaly labels are unavailable and this loss is zero.
    """

    def forward(
        self,
        z: torch.Tensor,
        labels: torch.Tensor,
        centroid: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            z:        (N, EMBEDDING_DIM) — embeddings from the encoder.
            labels:   (N,) — binary labels; 1 = anomaly, 0 = normal.
            centroid: (EMBEDDING_DIM,) — current normal traffic centroid z_0.

        Returns:
            Scalar loss: Σ_i II(A(t_i)) * ||z_i - z_0||²  (unweighted).
        """
        # Squared L2 distance from centroid for every sample in the batch
        dist_sq = ((z - centroid.unsqueeze(0)) ** 2).sum(dim=1)  # (N,)

        # Indicator function II(A(t_i)): 1 for anomaly, 0 for normal
        # Element-wise multiply so normal samples contribute 0 to the sum
        indicator = labels.float()  # (N,)

        return (indicator * dist_sq).sum()


class CombinedLoss(nn.Module):
    """
    L_total = L_contrastive + γ * L_anomaly  (paper Eq. 6).

    During self-supervised pre-training (labels=None), only L_contrastive
    is computed.  Pass labels during supervised fine-tuning to activate
    L_anomaly.

    Args:
        temperature: τ for NT-Xent loss (paper: 0.1).
        gamma:       γ — weight applied to L_anomaly at combination time (paper: 0.5).
    """

    def __init__(self, temperature: float = 0.1, gamma: float = 0.5) -> None:
        super().__init__()
        self.gamma            = gamma
        self.contrastive_loss = NTXentLoss(temperature=temperature)
        self.anomaly_loss     = AnomalyLoss()

    def forward(
        self,
        h: torch.Tensor,
        h_aug: torch.Tensor,
        z: torch.Tensor | None = None,
        labels: torch.Tensor | None = None,
        centroid: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, dict[str, float]]:
        """
        Args:
            h:        (N, PROJECTION_DIM) — projections of original samples.
            h_aug:    (N, PROJECTION_DIM) — projections of augmented samples.
            z:        (N, EMBEDDING_DIM) — encoder embeddings (needed for L_anomaly).
            labels:   (N,) — binary labels (0=normal, 1=anomaly); optional.
            centroid: (EMBEDDING_DIM,) — normal centroid; optional.

        Returns:
            (total_loss, loss_breakdown_dict)
        """
        l_contrastive = self.contrastive_loss(h, h_aug)

        l_anomaly = torch.tensor(0.0, device=h.device)
        if z is not None and labels is not None and centroid is not None:
            l_anomaly = self.anomaly_loss(z, labels, centroid)

        # γ weighting applied here — paper Eq. 6: L_total = L_contrastive + γ·L_anomaly
        total = l_contrastive + self.gamma * l_anomaly
        breakdown = {
            "loss_total":       total.item(),
            "loss_contrastive": l_contrastive.item(),
            "loss_anomaly":     l_anomaly.item(),   # unweighted, for logging
        }
        return total, breakdown
