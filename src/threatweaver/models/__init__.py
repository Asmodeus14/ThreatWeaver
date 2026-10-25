"""ThreatWeaver models package."""

from threatweaver.models.encoder import ThreatEncoder, ResidualBlock
from threatweaver.models.classifier import (
    ThreatClassifier,
    ThreatModelOutput,
    save_checkpoint,
    load_checkpoint,
    verify_checkpoint_file,
    compute_checkpoint_signature,
)
from threatweaver.models.novelty import (
    NoveltyDetector,
    NoveltyAssessment,
    PrototypeCluster,
)
from threatweaver.models.calibration import (
    TemperatureScaler,
    calibrate_temperature,
    compute_ece,
    compute_brier_score,
)

__all__ = [
    "ThreatEncoder",
    "ResidualBlock",
    "ThreatClassifier",
    "ThreatModelOutput",
    "save_checkpoint",
    "load_checkpoint",
    "verify_checkpoint_file",
    "compute_checkpoint_signature",
    "NoveltyDetector",
    "NoveltyAssessment",
    "PrototypeCluster",
    "TemperatureScaler",
    "calibrate_temperature",
    "compute_ece",
    "compute_brier_score",
]
