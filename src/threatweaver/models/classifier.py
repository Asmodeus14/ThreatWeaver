"""ThreatWeaver classification model and safe checkpoint management."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import warnings

import torch
import torch.nn as nn
import torch.nn.functional as F

from threatweaver.models import signing
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
        embedding_dim: int = 128,
        num_classes: int = 2,
        dropout: float = 0.2,
        temperature: float = 1.0,
        head_input: str = "embedding",
    ):
        super().__init__()
        self.input_dim = input_dim
        self.embedding_dim = embedding_dim
        self.num_classes = num_classes
        self.temperature = max(temperature, 0.01)
        self.head_input = head_input

        self.hidden_dims = list(hidden_dims) if hidden_dims is not None else [256, 128]
        self.dropout = dropout
        self.encoder = ThreatEncoder(
            input_dim=input_dim,
            hidden_dims=hidden_dims,
            embedding_dim=embedding_dim,
            dropout=dropout,
        )

        head_in_features = self.encoder.latent_dim if head_input == "latent" else embedding_dim

        # Classification head attached to embedding representation (or latent if legacy)
        self.head = nn.Sequential(
            nn.Linear(head_in_features, 64),
            nn.LayerNorm(64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> ThreatModelOutput:
        latent, embeddings = self.encoder(x)
        features_for_head = latent if self.head_input == "latent" else embeddings
        logits = self.head(features_for_head)
        # Scaled softmax for calibrated uncertainty estimation
        scaled_logits = logits / self.temperature
        probabilities = F.softmax(scaled_logits, dim=-1)
        return ThreatModelOutput(
            logits=logits,
            probabilities=probabilities,
            embeddings=embeddings,
            latent_features=latent,
        )


def compute_checkpoint_signature(checkpoint_bytes: bytes) -> str:
    """Returns the SHA-256 digest of checkpoint bytes (integrity fingerprint, not a signature).

    Kept for API compatibility; authenticity is provided by Ed25519 (threatweaver.models.signing).
    """
    return hashlib.sha256(checkpoint_bytes).hexdigest()


def verify_checkpoint_file(checkpoint_path: str | Path) -> Tuple[bool, str]:
    """Verifies the Ed25519 signature of a checkpoint. Returns (is_valid, reason).

    Unsigned checkpoints are reported as NOT valid (fail-closed).
    """
    result = signing.verify_file(Path(checkpoint_path).resolve())
    return result.valid, result.reason


def save_checkpoint(
    model: ThreatClassifier,
    save_path: str | Path,
    feature_mean: Optional[List[float]] = None,
    feature_std: Optional[List[float]] = None,
    novelty_threshold: float = 0.5,
    prototypes: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    sign: bool = True,
) -> Path:
    """Safely saves model weights, preprocessing statistics, and schema metadata."""
    path = Path(save_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "input_dim": model.input_dim,
        "embedding_dim": getattr(model, "embedding_dim", 32),
        "hidden_dims": getattr(model, "hidden_dims", [256, 128]),
        "head_input": getattr(model, "head_input", "embedding"),
        "num_classes": model.num_classes,
        "state_dict": model.state_dict(),
        "temperature": model.temperature,
        "feature_mean": feature_mean,
        "feature_std": feature_std,
        "novelty_threshold": novelty_threshold,
        "prototypes": prototypes or [],
        "metadata": metadata or {},
    }

    torch.save(payload, path)

    stale_sig = signing.signature_path(path)
    if sign:
        signing.sign_file(path, role="local")
    elif stale_sig.is_file():
        stale_sig.unlink()  # never leave a signature describing different bytes

    return path


def load_checkpoint(
    checkpoint_path: str | Path,
    device: torch.device | str = "cpu",
    enforce_signature: bool = True,
    allow_unsigned: bool = False,
) -> Tuple[ThreatClassifier, Dict[str, Any]]:
    """Loads model weights and metadata after verifying the checkpoint's Ed25519 signature.

    Fail-closed: unsigned, tampered or untrusted checkpoints raise ValueError unless
    allow_unsigned=True (or THREATWEAVER_ALLOW_UNSIGNED_MODELS=1), which only emits a warning.
    ``enforce_signature`` is kept for backward compatibility; enforcement is now the default.
    """
    path = Path(checkpoint_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Checkpoint not found at: {path}")

    result = signing.verify_file(path)
    if not result.valid:
        if signing.unsigned_allowed(allow_unsigned):
            warnings.warn(
                f"Loading unsigned or unverified checkpoint {path.name} ({result.reason}). Research use only.",
                UserWarning,
                stacklevel=2,
            )
        else:
            raise ValueError(f"Checkpoint integrity verification failed for {path}: {result.reason}")

    # Hardened deserialization with weights_only=True
    try:
        data = torch.load(path, map_location=device, weights_only=True)
    except Exception as e:
        raise ValueError(f"Failed to load checkpoint safely from {path}: {str(e)}")

    schema = data.get("schema_version")
    if schema != SCHEMA_VERSION:
        raise ValueError(
            f"Checkpoint schema version mismatch: expected {SCHEMA_VERSION}, found {schema}"
        )

    input_dim = data.get("input_dim", 256)
    num_classes = data.get("num_classes", 2)
    temp = data.get("temperature", 1.0)
    state_dict = data.get("state_dict", {})

    # Auto-detect embedding_dim
    if "embedding_dim" in data:
        embedding_dim = int(data["embedding_dim"])
    elif "encoder.embedding_proj.weight" in state_dict:
        embedding_dim = int(state_dict["encoder.embedding_proj.weight"].shape[0])
    else:
        embedding_dim = 128

    # Auto-detect head_input (backward compatible with legacy checkpoints)
    if "head_input" in data:
        head_input = data["head_input"]
    elif "head.0.weight" in state_dict:
        head_in = state_dict["head.0.weight"].shape[1]
        head_input = "embedding" if head_in == embedding_dim else "latent"
    else:
        head_input = "embedding"

    hidden_dims = data.get("hidden_dims") or [256, 128]  # v0.1 checkpoints predate this field
    model = ThreatClassifier(
        input_dim=input_dim,
        hidden_dims=list(hidden_dims),
        embedding_dim=embedding_dim,
        num_classes=num_classes,
        temperature=temp,
        head_input=head_input,
    )
    model.load_state_dict(state_dict)
    model.to(device)
    model.eval()

    extra_meta = data.get("metadata", {})
    if not isinstance(extra_meta, dict):
        extra_meta = {}

    metadata = {
        "schema_version": schema,
        "embedding_dim": embedding_dim,
        "head_input": head_input,
        "feature_mean": data.get("feature_mean"),
        "feature_std": data.get("feature_std"),
        "novelty_threshold": data.get("novelty_threshold", 0.5),
        "prototypes": data.get("prototypes", []),
        "extra": extra_meta,
    }

    return model, metadata
