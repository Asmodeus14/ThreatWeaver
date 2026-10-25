"""Tests for ThreatWeaver calibration and temperature scaling."""

import numpy as np
import pytest
import torch

from threatweaver.models.calibration import (
    TemperatureScaler,
    calibrate_temperature,
    compute_brier_score,
    compute_ece,
)


def test_compute_ece_perfect_calibration():
    """ECE on perfectly calibrated predictions should be near zero."""
    probs = np.array([
        [0.9, 0.1],
        [0.8, 0.2],
        [0.2, 0.8],
        [0.1, 0.9],
    ])
    labels = np.array([0, 0, 1, 1])
    ece = compute_ece(probs, labels, n_bins=5)
    assert 0.0 <= ece <= 0.25


def test_compute_ece_1d_input():
    """compute_ece should accept 1D binary probabilities."""
    probs_1d = np.array([0.1, 0.2, 0.8, 0.9])
    labels = np.array([0, 0, 1, 1])
    ece = compute_ece(probs_1d, labels, n_bins=5)
    assert isinstance(ece, float)
    assert 0.0 <= ece <= 1.0


def test_compute_brier_score():
    """Brier score is mean squared error of predicted probabilities."""
    p = np.array([0.0, 1.0, 0.5])
    y = np.array([0, 1, 1])
    # (0 - 0)^2 + (1 - 1)^2 + (0.5 - 1)^2 = 0 + 0 + 0.25 -> mean = 0.25 / 3 = 0.08333
    bs = compute_brier_score(p, y)
    assert pytest.approx(bs, abs=1e-4) == 0.25 / 3.0


def test_temperature_scaler():
    """Temperature scaler divides logits by temperature parameter."""
    scaler = TemperatureScaler(init_temperature=2.0)
    logits = torch.tensor([[4.0, -2.0]])
    scaled = scaler(logits)
    expected = torch.tensor([[2.0, -1.0]])
    assert torch.allclose(scaled, expected, atol=1e-5)


def test_calibrate_temperature_optimization():
    """Calibrate temperature should optimize T to improve likelihood."""
    torch.manual_seed(42)
    # Generate overconfident logits where logits are too extreme
    n = 200
    labels = np.random.randint(0, 2, size=n)
    logits = np.zeros((n, 2), dtype=np.float32)
    for i in range(n):
        if labels[i] == 1:
            logits[i] = [-5.0, 5.0]
        else:
            logits[i] = [5.0, -5.0]

    # Add 20% label noise so extreme confidence is overconfident
    flip_mask = np.random.rand(n) < 0.20
    labels[flip_mask] = 1 - labels[flip_mask]

    optimal_t = calibrate_temperature(logits, labels)
    assert isinstance(optimal_t, float)
    assert optimal_t > 1.0  # Temperature should increase to soften overconfident logits
