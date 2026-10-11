"""Bounded replay memory buffer for continual learning in ThreatWeaver."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


@dataclass
class ReplaySample:
    """An individual verified sample stored in the replay buffer."""
    features: np.ndarray       # Shape: (input_dim,)
    label: int                 # 0 or 1
    sample_id: str
    family: str
    timestamp: int
    uncertainty: float = 0.0
    embedding: Optional[np.ndarray] = None


class ReplayBuffer:
    """Bounded-capacity memory buffer preserving verified prior examples."""

    def __init__(self, capacity: int = 500, seed: int = 42):
        self.capacity = max(capacity, 1)
        self.rng = np.random.default_rng(seed)
        self.buffer: List[ReplaySample] = []

    def __len__(self) -> int:
        return len(self.buffer)

    def add(self, sample: ReplaySample) -> None:
        """Adds a sample to the buffer, evicting if over capacity."""
        if len(self.buffer) < self.capacity:
            self.buffer.append(sample)
        else:
            # Random eviction (Reservoir sampling principle)
            evict_idx = self.rng.integers(0, len(self.buffer))
            self.buffer[evict_idx] = sample

    def extend(self, samples: List[ReplaySample]) -> None:
        """Adds multiple samples with bounded capacity enforcement."""
        for s in samples:
            self.add(s)

    def sample(self, n: int) -> List[ReplaySample]:
        """Samples up to n items uniformly at random without replacement."""
        if not self.buffer:
            return []
        sample_size = min(n, len(self.buffer))
        chosen_indices = self.rng.choice(len(self.buffer), size=sample_size, replace=False)
        return [self.buffer[i] for i in chosen_indices]

    def get_all(self) -> List[ReplaySample]:
        """Returns all currently buffered samples."""
        return list(self.buffer)

    def to_arrays(self) -> Tuple[np.ndarray, np.ndarray]:
        """Converts buffer contents to feature and label arrays."""
        if not self.buffer:
            return np.empty((0, 256), dtype=np.float32), np.empty((0,), dtype=np.int64)
        X = np.stack([s.features for s in self.buffer], axis=0)
        y = np.array([s.label for s in self.buffer], dtype=np.int64)
        return X, y
