"""Model output calibration and temperature scaling for ThreatWeaver.

Ensures predicted malware probabilities correspond to empirical frequencies,
reducing overconfidence on out-of-distribution and ambiguous binaries.
"""

from __future__ import annotations

from typing import Tuple, Union

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim


def compute_ece(
    probabilities: np.ndarray,
    labels: np.ndarray,
    n_bins: int = 10,
) -> float:
    """Computes Expected Calibration Error (ECE) across confidence bins.

    Args:
        probabilities: Array of predicted class probabilities of shape (N, C) or (N,).
        labels: Ground truth binary labels of shape (N,).
        n_bins: Number of confidence bins (default 10).

    Returns:
        Scalar ECE between 0.0 and 1.0.
    """
    if probabilities.ndim == 1:
        # Binary probabilities: convert to (N, 2)
        p1 = probabilities.reshape(-1, 1)
        p0 = 1.0 - p1
        probs = np.hstack([p0, p1])
    else:
        probs = probabilities

    confidences = np.max(probs, axis=-1)
    predictions = np.argmax(probs, axis=-1)
    accuracies = (predictions == labels).astype(np.float64)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(labels)
    if n == 0:
        return 0.0

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        mask = (confidences > bin_lower) & (confidences <= bin_upper)
        bin_count = np.sum(mask)
        if bin_count > 0:
            bin_acc = np.mean(accuracies[mask])
            bin_conf = np.mean(confidences[mask])
            ece += (bin_count / n) * np.abs(bin_acc - bin_conf)

    return float(ece)


def compute_brier_score(
    malware_probabilities: np.ndarray,
    labels: np.ndarray,
) -> float:
    """Computes mean squared Brier score for binary predictions."""
    p = np.clip(malware_probabilities, 0.0, 1.0)
    y = np.clip(labels, 0, 1)
    return float(np.mean((p - y) ** 2))


class TemperatureScaler(nn.Module):
    """Post-hoc temperature scaling layer for logit calibration (Guo et al., 2017)."""

    def __init__(self, init_temperature: float = 1.0):
        super().__init__()
        self.temperature = nn.Parameter(torch.tensor([float(init_temperature)]))

    def forward(self, logits: torch.Tensor) -> torch.Tensor:
        """Scales logits by 1/T."""
        temp = torch.clamp(self.temperature, min=0.01, max=100.0)
        return logits / temp


def calibrate_temperature(
    logits: Union[np.ndarray, torch.Tensor],
    labels: Union[np.ndarray, torch.Tensor],
    max_iter: int = 100,
    lr: float = 0.01,
) -> float:
    """Optimizes temperature T on validation logits to minimize negative log-likelihood.

    Args:
        logits: Unnormalized logits of shape (N, C).
        labels: True integer labels of shape (N,).
        max_iter: Maximum optimization iterations.
        lr: Learning rate for optimizer.

    Returns:
        Optimal temperature T > 0.
    """
    if isinstance(logits, np.ndarray):
        logits_t = torch.tensor(logits, dtype=torch.float32)
    else:
        logits_t = logits.detach().clone().float()

    if isinstance(labels, np.ndarray):
        labels_t = torch.tensor(labels, dtype=torch.long)
    else:
        labels_t = labels.detach().clone().long()

    scaler = TemperatureScaler(init_temperature=1.0)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.LBFGS([scaler.temperature], lr=lr, max_iter=max_iter)

    def closure():
        optimizer.zero_grad()
        loss = criterion(scaler(logits_t), labels_t)
        loss.backward()
        return loss

    try:
        optimizer.step(closure)
    except Exception:
        # Fallback to Adam if LBFGS encounters line search issue
        adam_opt = optim.Adam([scaler.temperature], lr=lr)
        for _ in range(max_iter):
            adam_opt.zero_grad()
            loss = criterion(scaler(logits_t), labels_t)
            loss.backward()
            adam_opt.step()

    optimal_t = float(torch.clamp(scaler.temperature, min=0.05, max=10.0).item())
    return optimal_t
