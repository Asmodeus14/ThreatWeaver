"""Evaluation metrics for malware classification and endpoint safety."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


@dataclass
class ClassificationMetrics:
    """Comprehensive evaluation metrics for static PE detection."""
    macro_f1: float
    benign_precision: float
    benign_recall: float
    benign_f1: float
    malware_precision: float
    malware_recall: float  # True Positive Rate (TPR)
    malware_f1: float
    false_positive_rate: float  # FPR on benign files (critical for AV)
    false_negative_rate: float  # FNR on malware files
    total_samples: int
    inference_latency_ms: float = 0.0


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    inference_time_sec: float = 0.0,
) -> ClassificationMetrics:
    """Computes precisely defined classification and AV safety metrics."""
    assert len(y_true) == len(y_pred), "y_true and y_pred must have identical length"
    n_samples = len(y_true)
    if n_samples == 0:
        return ClassificationMetrics(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0)

    # Confusion matrix with label order [0, 1]
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # Rates
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # Macro F1
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    # Per-class metrics
    p_benign = float(precision_score(y_true, y_pred, pos_label=0, zero_division=0))
    r_benign = float(recall_score(y_true, y_pred, pos_label=0, zero_division=0))
    f1_benign = float(f1_score(y_true, y_pred, pos_label=0, zero_division=0))

    p_mal = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    r_mal = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1_mal = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))

    latency_ms = (inference_time_sec / max(n_samples, 1)) * 1000.0

    return ClassificationMetrics(
        macro_f1=macro_f1,
        benign_precision=p_benign,
        benign_recall=r_benign,
        benign_f1=f1_benign,
        malware_precision=p_mal,
        malware_recall=r_mal,
        malware_f1=f1_mal,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        total_samples=n_samples,
        inference_latency_ms=latency_ms,
    )
