"""ThreatWeaver evaluation package."""

from threatweaver.evaluation.metrics import (
    ClassificationMetrics,
    compute_classification_metrics,
)
from threatweaver.evaluation.forgetting import (
    ContinualEvaluationReport,
    compute_catastrophic_forgetting,
)

__all__ = [
    "ClassificationMetrics",
    "compute_classification_metrics",
    "ContinualEvaluationReport",
    "compute_catastrophic_forgetting",
]
