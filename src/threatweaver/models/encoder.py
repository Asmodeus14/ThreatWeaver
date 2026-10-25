"""Modular neural encoder for ThreatWeaver static features."""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import List, Tuple


class ResidualBlock(nn.Module):
    """Residual Multi-Layer Perceptron block with LayerNorm and Dropout."""

    def __init__(self, dim: int, dropout: float = 0.2):
        super().__init__()
        self.fc1 = nn.Linear(dim, dim)
        self.ln1 = nn.LayerNorm(dim)
        self.act1 = nn.GELU()
        self.drop1 = nn.Dropout(dropout)

        self.fc2 = nn.Linear(dim, dim)
        self.ln2 = nn.LayerNorm(dim)
        self.act2 = nn.GELU()
        self.drop2 = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        out = self.drop1(self.act1(self.ln1(self.fc1(x))))
        out = self.drop2(self.act2(self.ln2(self.fc2(out))))
        return out + residual


class ThreatEncoder(nn.Module):
    """Encodes static feature vectors into latent representations and normalized embeddings."""

    def __init__(
        self,
        input_dim: int = 256,
        hidden_dims: List[int] | None = None,
        embedding_dim: int = 128,
        dropout: float = 0.2,
    ):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [256, 128]

        self.input_dim = input_dim
        self.embedding_dim = embedding_dim
        self.latent_dim = hidden_dims[-1]

        # Initial projection
        layers: List[nn.Module] = [
            nn.Linear(input_dim, hidden_dims[0]),
            nn.LayerNorm(hidden_dims[0]),
            nn.GELU(),
            nn.Dropout(dropout),
        ]

        # Intermediate hidden layers with residual connections
        current_dim = hidden_dims[0]
        for next_dim in hidden_dims[1:]:
            if next_dim == current_dim:
                layers.append(ResidualBlock(current_dim, dropout=dropout))
            else:
                layers.extend([
                    nn.Linear(current_dim, next_dim),
                    nn.LayerNorm(next_dim),
                    nn.GELU(),
                    nn.Dropout(dropout),
                ])
                current_dim = next_dim

        self.backbone = nn.Sequential(*layers)

        # Embedding projection head (maps latent features to L2-normalized embedding space)
        self.embedding_proj = nn.Linear(self.latent_dim, embedding_dim)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Returns tuple of (latent_features, l2_normalized_embeddings)."""
        latent = self.backbone(x)
        raw_emb = self.embedding_proj(latent)
        # Unit sphere normalization for cosine distance & similarity
        norm_emb = F.normalize(raw_emb, p=2, dim=-1)
        return latent, norm_emb
