"""ThreatWeaver classification model and safe checkpoint management."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

from threatweaver.models.encoder import ThreatEncoder

SCHEMA_VERSION = "1.0"



@dataclass
class ThreatModelOutput:
    """Standardized output of ThreatWeaver neural model."""
    logits: torch.Tensor          # Shape: (batch_size, num_classes)
    probabilities: torch.Tensor   # Shape: (batch_size, num_classes)
    embeddings: torch.Tensor      # Shape: (batch_size, embedding_dim), L2-normalized
    latent_features: torch.Tensor # Shape: (batch_size, latent_dim)


class ThreatClassifier(nn.Module):
    """Deep learning classifier for static malware detection."""

    def __init__(
        self,
        input_dim: int = 256,
        hidden_dims: List[int] | None = None,
        embedding_dim: int = 32,
        num_classes: int = 2,
        dropout: float = 0.2,
        temperature: float = 1.0,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.num_classes = num_classes
        self.temperature = max(temperature, 0.01)

        self.encoder = ThreatEncoder(
            input_dim=input_dim,
            hidden_dims=hidden_dims,
            embedding_dim=embedding_dim,
            dropout=dropout,
        )

        # Classification head attached to latent representation
        self.head = nn.Sequential(
            nn.Linear(self.encoder.latent_dim, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> ThreatModelOutput:
        latent, embeddings = self.encoder(x)
        logits = self.head(latent)
        # Scaled softmax for calibrated uncertainty estimation
        scaled_logits = logits / self.temperature
        probabilities = F.softmax(scaled_logits, dim=-1)
        return ThreatModelOutput(
            logits=logits,
            probabilities=probabilities,
            embeddings=embeddings,
            latent_features=latent,
        )


def save_checkpoint(
    model: ThreatClassifier,
    save_path: str | Path,
    feature_mean: Optional[List[float]] = None,
    feature_std: Optional[List[float]] = None,
    novelty_threshold: float = 0.5,
    metadata: Optional[Dict[str, Any]] = None,
) -> Path:
    """Safely saves model weights, preprocessing statistics, and schema metadata."""
    path = Path(save_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "input_dim": model.input_dim,
        "num_classes": model.num_classes,
        "state_dict": model.state_dict(),
        "temperature": model.temperature,
        "feature_mean": feature_mean,
        "feature_std": feature_std,
        "novelty_threshold": novelty_threshold,
        "metadata": metadata or {},
    }

    torch.save(payload, path)
    return path


def load_checkpoint(
    checkpoint_path: str | Path,
    device: torch.device | str = "cpu",
) -> Tuple[ThreatClassifier, Dict[str, Any]]:
    """Safely loads model weights and metadata from checkpoint with validation."""
    path = Path(checkpoint_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Checkpoint not found at: {path}")

    # Use weights_only=False carefully or load state dict
    try:
        data = torch.load(path, map_location=device, weights_only=False)
    except Exception as e:
        raise ValueError(f"Failed to load checkpoint from {path}: {str(e)}")

    schema = data.get("schema_version")
    if schema != SCHEMA_VERSION:
        raise ValueError(
            f"Checkpoint schema version mismatch: expected {SCHEMA_VERSION}, found {schema}"
        )

    input_dim = data.get("input_dim", 256)
    num_classes = data.get("num_classes", 2)
    temp = data.get("temperature", 1.0)

    model = ThreatClassifier(
        input_dim=input_dim,
        num_classes=num_classes,
        temperature=temp,
    )
    model.load_state_dict(data["state_dict"])
    model.to(device)
    model.eval()

    metadata = {
        "schema_version": schema,
        "feature_mean": data.get("feature_mean"),
        "feature_std": data.get("feature_std"),
        "novelty_threshold": data.get("novelty_threshold", 0.5),
        "extra": data.get("metadata", {}),
    }

    return model, metadata
