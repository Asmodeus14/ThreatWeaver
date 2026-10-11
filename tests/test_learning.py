"""Tests for continual learning, replay selection, and forgetting metrics."""

import numpy as np
import pytest

from threatweaver.learning.replay_buffer import ReplayBuffer, ReplaySample
from threatweaver.learning.selection import (
    NoReplaySelector,
    RandomReplaySelector,
    UncertaintyReplaySelector,
    UncertaintyDiversityReplaySelector,
    get_replay_selector,
)
from threatweaver.evaluation.metrics import compute_classification_metrics
from threatweaver.evaluation.forgetting import compute_catastrophic_forgetting


def test_replay_buffer_capacity_and_eviction():
    """Validates bounded capacity enforcement in ReplayBuffer."""
    buffer = ReplayBuffer(capacity=5, seed=42)
    assert len(buffer) == 0

    for i in range(10):
        buffer.add(
            ReplaySample(
                features=np.zeros(256, dtype=np.float32),
                label=i % 2,
                sample_id=f"sample_{i}",
                family="Family",
                timestamp=1000 + i,
            )
        )

    # Capacity must not be exceeded
    assert len(buffer) == 5
    sampled = buffer.sample(3)
    assert len(sampled) == 3


def test_replay_selection_strategies():
    """Validates sample selection across the 4 replay strategies."""
    candidates = [
        ReplaySample(
            features=np.random.randn(256).astype(np.float32),
            label=i % 2,
            sample_id=f"s_{i}",
            family="Family",
            timestamp=i,
            uncertainty=float(i) / 10.0,  # s_9 has highest uncertainty (0.9)
            embedding=np.random.randn(32).astype(np.float32),
        )
        for i in range(10)
    ]

    # Strategy A: None
    none_sel = get_replay_selector("none", budget=3)
    assert len(none_sel.select(candidates)) == 0

    # Strategy B: Random
    rand_sel = get_replay_selector("random", budget=3, seed=42)
    chosen_rand = rand_sel.select(candidates)
    assert len(chosen_rand) == 3

    # Strategy C: Uncertainty
    unc_sel = get_replay_selector("uncertainty", budget=3)
    chosen_unc = unc_sel.select(candidates)
    assert len(chosen_unc) == 3
    # Top uncertain must be sample 9, 8, 7
    assert chosen_unc[0].sample_id == "s_9"
    assert chosen_unc[1].sample_id == "s_8"

    # Strategy D: Uncertainty + Diversity
    div_sel = get_replay_selector("uncertainty_diversity", budget=3, seed=42)
    chosen_div = div_sel.select(candidates)
    assert len(chosen_div) == 3


def test_classification_metrics_and_fpr():
    """Validates accurate computation of classification metrics and FPR."""
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    # 1 false positive on benign (predicted 1 when true 0), 1 false negative (predicted 0 when true 1)
    y_pred = np.array([0, 0, 0, 1, 0, 1, 1, 1])

    metrics = compute_classification_metrics(y_true, y_pred, inference_time_sec=0.01)

    assert metrics.false_positive_rate == 0.25  # 1 / 4
    assert metrics.false_negative_rate == 0.25  # 1 / 4
    assert metrics.benign_precision == 0.75     # 3 / (3 + 1)
    assert metrics.malware_precision == 0.75    # 3 / (3 + 1)
    assert metrics.inference_latency_ms > 0.0


def test_catastrophic_forgetting_calculation():
    """Validates mathematical correctness of catastrophic forgetting F_T."""
    # Matrix R[i, j]: performance on batch j after training on batch i
    # Batch 0: initial 0.90, drops to 0.70 at step 1, 0.60 at step 2 -> forgetting = 0.90 - 0.60 = 0.30
    # Batch 1: initial 0.85, drops to 0.80 at step 2 -> forgetting = 0.85 - 0.80 = 0.05
    r_matrix = np.array([
        [0.90, 0.00, 0.00],
        [0.70, 0.85, 0.00],
        [0.60, 0.80, 0.88],
    ])

    forgetting, bwt = compute_catastrophic_forgetting(r_matrix)
    # Expected mean forgetting = (0.30 + 0.05) / 2 = 0.175
    assert np.isclose(forgetting, 0.175, atol=1e-3)
    # Expected BWT = ((0.60 - 0.90) + (0.80 - 0.85)) / 2 = (-0.30 - 0.05) / 2 = -0.175
    assert np.isclose(bwt, -0.175, atol=1e-3)
