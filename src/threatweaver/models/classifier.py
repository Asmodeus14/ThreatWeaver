"""ThreatWeaver classification model and safe checkpoint management."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import warnings

import torch
import torch.nn as nn
import torch.nn.functional as F

from threatweaver.models.encoder import ThreatEncoder

SCHEMA_VERSION = "1.0"
CHECKPOINT_HMAC_KEY = b"ThreatWeaver-v1.0-checkpoint-integrity-key-9b7a"



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


def compute_checkpoint_signature(checkpoint_bytes: bytes, key: bytes = CHECKPOINT_HMAC_KEY) -> str:
    """Computes HMAC-SHA256 signature for checkpoint file bytes."""
    return hmac.new(key, checkpoint_bytes, hashlib.sha256).hexdigest()


def verify_checkpoint_file(
    checkpoint_path: str | Path,
    key: bytes = CHECKPOINT_HMAC_KEY,
) -> Tuple[bool, str]:
    """Verifies HMAC signature of a checkpoint if signature file exists.

    Returns (is_valid, reason).
    """
    path = Path(checkpoint_path).resolve()
    sig_path = path.with_suffix(path.suffix + ".sig")
    if not sig_path.is_file():
        return True, "No signature file found (unsigned legacy checkpoint)"

    try:
        expected_sig = sig_path.read_text(encoding="utf-8").strip()
        data = path.read_bytes()
        actual_sig = compute_checkpoint_signature(data, key)
        if hmac.compare_digest(expected_sig, actual_sig):
            return True, "Signature valid"
        return False, f"Signature mismatch (expected {expected_sig[:12]}..., got {actual_sig[:12]}...)"
    except Exception as e:
        return False, f"Error verifying signature: {str(e)}"


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

    if sign:
        data = path.read_bytes()
        sig = compute_checkpoint_signature(data)
        sig_path = path.with_suffix(path.suffix + ".sig")
        sig_path.write_text(sig, encoding="utf-8")

    return path


def load_checkpoint(
    checkpoint_path: str | Path,
    device: torch.device | str = "cpu",
    enforce_signature: bool = False,
) -> Tuple[ThreatClassifier, Dict[str, Any]]:
    """Safely loads model weights and metadata from checkpoint with validation."""
    path = Path(checkpoint_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Checkpoint not found at: {path}")

    # Integrity verification
    valid, reason = verify_checkpoint_file(path)
    if not valid:
        raise ValueError(f"Checkpoint integrity verification failed for {path}: {reason}")
    if "No signature file" in reason:
        if enforce_signature:
            raise ValueError(f"Checkpoint {path} is unsigned and enforce_signature=True.")
        warnings.warn(
            f"Loading unsigned checkpoint from {path.name}. Signatures are recommended for production models.",
            UserWarning,
            stacklevel=2,
        )

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

    model = ThreatClassifier(
        input_dim=input_dim,
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
