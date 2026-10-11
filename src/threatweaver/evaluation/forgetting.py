"""Catastrophic forgetting and continual learning evaluation protocols."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import numpy as np


@dataclass
class ContinualEvaluationReport:
    """Rigorous continual learning performance summary."""
    strategy_id: str
    strategy_name: str
    num_batches: int
    r_matrix: np.ndarray             # Performance matrix R[i, j] (evaluated on batch j after training on batch i)
    catastrophic_forgetting: float   # Mean forgetting across all prior batches F_T
    backward_transfer: float         # BWT: average change from initial learning performance
    final_macro_f1: float            # Performance on all batches after final step
    final_fpr: float                 # Final FPR on benign files
    training_time_sec: float
    peak_ram_mb: float = 0.0
    model_size_kb: float = 0.0


def compute_catastrophic_forgetting(r_matrix: np.ndarray) -> Tuple[float, float]:
    """Computes Catastrophic Forgetting (F_T) and Backward Transfer (BWT).
    
    Given matrix R where R[i, j] is the Macro-F1 on test batch j after training on batch i:
    Forgetting on task j at final step T:
        f_j = max_{k in {j ... T-1}} R[k, j] - R[T, j]
    Average Forgetting:
        F_T = (1 / (T - 1)) * sum_{j=1}^{T-1} f_j
    Backward Transfer:
        BWT = (1 / (T - 1)) * sum_{j=1}^{T-1} (R[T, j] - R[j, j])
    """
    T = r_matrix.shape[0]
    if T <= 1:
        return 0.0, 0.0

    forgetting_values = []
    bwt_values = []

    for j in range(T - 1):
        # Best performance on batch j before or at step T-1
        peak_prior = np.max(r_matrix[j : T - 1, j])
        final_perf = r_matrix[T - 1, j]
        forgetting = max(0.0, float(peak_prior - final_perf))
        forgetting_values.append(forgetting)

        # Backward transfer
        initial_perf = r_matrix[j, j]
        bwt = float(final_perf - initial_perf)
        bwt_values.append(bwt)

    avg_forgetting = float(np.mean(forgetting_values)) if forgetting_values else 0.0
    avg_bwt = float(np.mean(bwt_values)) if bwt_values else 0.0

    return avg_forgetting, avg_bwt
