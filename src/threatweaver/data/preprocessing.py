"""Data preprocessing and feature scaling for ThreatWeaver."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


class FeatureScaler:
    """Standardizes feature vectors using mean and standard deviation.
    
    Strictly fitted on training data only to prevent data leakage.
    """

    def __init__(self, eps: float = 1e-6):
        self.eps = eps
        self.mean: Optional[np.ndarray] = None
        self.std: Optional[np.ndarray] = None
        self.fitted: bool = False

    def fit(self, X: np.ndarray) -> "FeatureScaler":
        """Fits mean and std on training array X."""
        X_clean = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=-1.0)
        self.mean = np.mean(X_clean, axis=0)
        self.std = np.std(X_clean, axis=0)
        # Avoid division by zero for invariant features
        self.std[self.std < self.eps] = 1.0
        self.fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transforms X using fitted mean and std."""
        if not self.fitted or self.mean is None or self.std is None:
            raise RuntimeError("FeatureScaler must be fitted before calling transform.")
        X_clean = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=-1.0)
        return ((X_clean - self.mean) / self.std).astype(np.float32)

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes scaler statistics for checkpoints and production deployment."""
        if not self.fitted:
            return {"fitted": False}
        return {
            "fitted": True,
            "mean": self.mean.tolist() if self.mean is not None else [],
            "std": self.std.tolist() if self.std is not None else [],
            "eps": self.eps,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeatureScaler":
        """Restores scaler from dictionary."""
        scaler = cls(eps=data.get("eps", 1e-6))
        if data.get("fitted", False):
            scaler.mean = np.array(data["mean"], dtype=np.float32)
            scaler.std = np.array(data["std"], dtype=np.float32)
            scaler.fitted = True
        return scaler
