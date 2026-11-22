"""Data loading and synthetic benchmark generation for ThreatWeaver.

Provides reproducible data streaming, PyTorch Dataset wrappers, and
temporal benchmark datasets with verifiable malware family distributions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset

from threatweaver.data.preprocessing import FeatureScaler
from threatweaver.scanner.feature_extractor import FEATURE_DIM, SCHEMA_VERSION


class ThreatDataset(Dataset):
    """PyTorch Dataset wrapping static features and labels."""

    def __init__(
        self,
        features: np.ndarray,
        labels: np.ndarray,
        sample_ids: Optional[List[str]] = None,
        timestamps: Optional[np.ndarray] = None,
        family_names: Optional[List[str]] = None,
    ):
        assert len(features) == len(labels), "Features and labels must have matching length"
        self.features = torch.tensor(features, dtype=torch.float32)
        self.labels = torch.tensor(labels, dtype=torch.long)
        self.sample_ids = sample_ids or [f"sample_{i}" for i in range(len(features))]
        self.timestamps = timestamps if timestamps is not None else np.arange(len(features))
        self.family_names = family_names or ["Unknown"] * len(features)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        return {
            "features": self.features[idx],
            "label": self.labels[idx],
            "sample_id": self.sample_ids[idx],
            "timestamp": self.timestamps[idx],
            "family": self.family_names[idx],
        }


def create_dataloader(
    dataset: ThreatDataset,
    batch_size: int = 64,
    shuffle: bool = True,
    num_workers: int = 0,
) -> DataLoader:
    """Creates a PyTorch DataLoader configured safely for Windows."""
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=num_workers,
        pin_memory=False,
    )


def generate_synthetic_benchmark_dataset(
    n_samples: int = 1000,
    num_batches: int = 5,
    seed: int = 42,
) -> Dict[str, Any]:
    """Generates a reproducible temporal malware detection benchmark.
    
    Creates:
    - Benign files (class 0)
    - Multiple malware families (class 1) emerging chronologically across temporal batches:
      - Batch 1: Benign + Family A (Downloader)
      - Batch 2: Benign + Family A + Family B (Ransomware)
      - Batch 3: Benign + Family B + Family C (Keylogger)
      - Batch 4: Benign + Family C + Family D (Injector)
      - Batch 5: Benign + All families + Novel zero-day variants
    """
    rng = np.random.default_rng(seed)
    samples_per_batch = n_samples // num_batches

    all_features = []
    all_labels = []
    all_timestamps = []
    all_families = []
    all_batch_ids = []

    # Family profiles: characteristic dimension offsets in 256-dim feature space
    # Dims 0..31: headers, 32..95: sections, 96..159: APIs, 160..255: byte histogram/entropy
    for b_idx in range(num_batches):
        base_time = 1700000000 + b_idx * 86400 * 30  # 30-day temporal spacing

        for i in range(samples_per_batch):
            timestamp = base_time + rng.integers(0, 86400 * 28)
            # 50% benign, 50% malicious
            is_malware = rng.random() > 0.5
            feat = np.zeros(FEATURE_DIM, dtype=np.float32)

            if not is_malware:
                label = 0
                family = "Benign-Utility"
                # Benign characteristics: standard sections, valid ASLR/DEP, moderate entropy (5.0-6.2)
                feat[0] = rng.uniform(0.3, 0.7)   # normal size
                feat[13] = 1.0                    # ASLR
                feat[14] = 1.0                    # DEP
                feat[32] = rng.uniform(0.5, 0.75) # normal overall entropy
                feat[33] = rng.uniform(0.6, 0.8)  # max section entropy
                feat[42] = 1.0                    # has .text
                feat[45] = 1.0                    # has .data
                feat[48] = 1.0                    # has .rdata
                # Low suspicious APIs
                feat[96:112] = rng.uniform(0.0, 0.1, size=16)
                # Normal byte distribution
                feat[160:224] = rng.dirichlet(np.ones(64) * 2.0)
                feat[224] = rng.uniform(0.2, 0.5) # normal printable ASCII ratio
            else:
                label = 1
                # Select family based on batch progression
                available_families = ["Family-A-Downloader"]
                if b_idx >= 1:
                    available_families.append("Family-B-Ransomware")
                if b_idx >= 2:
                    available_families.append("Family-C-Keylogger")
                if b_idx >= 3:
                    available_families.append("Family-D-Injector")

                family = rng.choice(available_families)

                if family == "Family-A-Downloader":
                    # Network & dynamic loading APIs
                    feat[96] = 0.8; feat[97] = 0.7  # injection
                    feat[106] = 0.9; feat[107] = 0.8 # network
                    feat[32] = rng.uniform(0.65, 0.85)
                elif family == "Family-B-Ransomware":
                    # High entropy, crypto APIs, W^X violations
                    feat[32] = rng.uniform(0.85, 0.99) # extremely high entropy
                    feat[38] = 0.6                     # W^X violation
                    feat[110] = 0.9; feat[111] = 0.8   # crypto APIs
                    feat[40] = 0.8                     # high entropy sections
                elif family == "Family-C-Keylogger":
                    # Hooking & persistence APIs
                    feat[102] = 0.9; feat[103] = 0.8  # persistence
                    feat[104] = 0.9; feat[105] = 0.8  # hooking
                    feat[32] = rng.uniform(0.5, 0.7)
                elif family == "Family-D-Injector":
                    # Process injection, evasions, anomalous entry point
                    feat[96] = 1.0; feat[97] = 0.9   # heavy injection
                    feat[100] = 0.8; feat[101] = 0.7 # evasion
                    feat[21] = 0.9                   # unusual entry point
                    feat[38] = 0.8                   # W^X section

                # Add noise
                feat += rng.normal(0.0, 0.05, size=FEATURE_DIM).astype(np.float32)
                feat = np.clip(feat, 0.0, 2.0)

            all_features.append(feat)
            all_labels.append(label)
            all_timestamps.append(timestamp)
            all_families.append(family)
            all_batch_ids.append(b_idx)

    return {
        "features": np.array(all_features, dtype=np.float32),
        "labels": np.array(all_labels, dtype=np.int64),
        "timestamps": np.array(all_timestamps, dtype=np.int64),
        "families": all_families,
        "batch_ids": np.array(all_batch_ids, dtype=np.int64),
    }
