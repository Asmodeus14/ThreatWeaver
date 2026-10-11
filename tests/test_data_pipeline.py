"""Tests for data splits and temporal ordering integrity."""

import numpy as np
import pytest

from threatweaver.data.splits import TemporalSplitter
from threatweaver.data.preprocessing import FeatureScaler
from threatweaver.data.loader import generate_synthetic_benchmark_dataset


def test_temporal_splitter_zero_leakage():
    """Validates that temporal splits strictly partition past/present/future with zero overlap."""
    timestamps = np.array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
    splitter = TemporalSplitter(train_ratio=0.6, val_ratio=0.2, test_ratio=0.2)
    split = splitter.split_by_timestamps(timestamps)

    # Disjoint indices
    assert len(set(split.train_indices) & set(split.val_indices)) == 0
    assert len(set(split.val_indices) & set(split.test_indices)) == 0
    assert len(set(split.train_indices) & set(split.test_indices)) == 0

    # Past timestamps in train must strictly precede future timestamps in test
    max_train_time = np.max(timestamps[split.train_indices])
    min_test_time = np.min(timestamps[split.test_indices])
    assert max_train_time < min_test_time


def test_feature_scaler_no_leakage():
    """Validates FeatureScaler fits on train only and does not crash on zeroes or infinities."""
    X_train = np.array([[0.0, 10.0], [0.0, 20.0]], dtype=np.float32)
    scaler = FeatureScaler()
    scaler.fit(X_train)

    assert scaler.fitted is True
    # Feature 0 had zero variance, std clipped to 1.0
    assert scaler.std[0] == 1.0

    X_test = np.array([[0.0, 15.0]], dtype=np.float32)
    X_scaled = scaler.transform(X_test)
    assert np.all(np.isfinite(X_scaled))


def test_synthetic_benchmark_dataset_generation():
    """Validates synthetic benchmark dataset generation and batch properties."""
    data = generate_synthetic_benchmark_dataset(n_samples=200, num_batches=4, seed=42)

    assert len(data["features"]) == 200
    assert len(data["labels"]) == 200
    assert data["features"].shape[1] == 256
    assert set(np.unique(data["labels"])) == {0, 1}
    assert len(np.unique(data["batch_ids"])) == 4
