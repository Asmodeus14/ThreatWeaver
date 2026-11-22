"""ThreatWeaver data package."""

from threatweaver.data.preprocessing import FeatureScaler
from threatweaver.data.splits import TemporalSplitter, DatasetSplit
from threatweaver.data.loader import (
    ThreatDataset,
    create_dataloader,
    generate_synthetic_benchmark_dataset,
)
from threatweaver.data.ember_loader import (
    EMBERDatasetLoader,
    EMBERMetadata,
    EMBER_RAW_FEATURE_DIM,
    generate_synthetic_ember_jsonl,
)

__all__ = [
    "FeatureScaler",
    "TemporalSplitter",
    "DatasetSplit",
    "ThreatDataset",
    "create_dataloader",
    "generate_synthetic_benchmark_dataset",
    "EMBERDatasetLoader",
    "EMBERMetadata",
    "EMBER_RAW_FEATURE_DIM",
    "generate_synthetic_ember_jsonl",
]
