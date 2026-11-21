"""Data splitting protocols for ThreatWeaver.

Guarantees temporal ordering preservation and prevents look-ahead leakage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

import numpy as np


@dataclass
class DatasetSplit:
    """Indexed partition of dataset samples."""
    train_indices: np.ndarray
    val_indices: np.ndarray
    test_indices: np.ndarray


class TemporalSplitter:
    """Splits data strictly according to chronological ordering."""

    def __init__(
        self,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
    ):
        total = train_ratio + val_ratio + test_ratio
        if not np.isclose(total, 1.0):
            raise ValueError(f"Split ratios must sum to 1.0, got {total}")
        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio

    def split_by_timestamps(
        self, timestamps: np.ndarray
    ) -> DatasetSplit:
        """Sorts chronologically and partitions into past -> present -> future."""
        n_samples = len(timestamps)
        sorted_indices = np.argsort(timestamps)

        train_end = int(n_samples * self.train_ratio)
        val_end = train_end + int(n_samples * self.val_ratio)

        train_idx = sorted_indices[:train_end]
        val_idx = sorted_indices[train_end:val_end]
        test_idx = sorted_indices[val_end:]

        # Validate zero index overlap
        assert len(set(train_idx).intersection(set(val_idx))) == 0
        assert len(set(val_idx).intersection(set(test_idx))) == 0
        assert len(set(train_idx).intersection(set(test_idx))) == 0

        return DatasetSplit(
            train_indices=train_idx,
            val_indices=val_idx,
            test_indices=test_idx,
        )

    def partition_temporal_batches(
        self, timestamps: np.ndarray, num_batches: int = 5
    ) -> List[np.ndarray]:
        """Partitions chronologically sorted indices into B sequential temporal batches."""
        sorted_indices = np.argsort(timestamps)
        return np.array_split(sorted_indices, num_batches)
