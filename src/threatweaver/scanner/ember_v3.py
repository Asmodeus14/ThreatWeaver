"""EMBER2024 feature version 3 (2,568-D) via the official `thrember` extractor.

Training and inference use the SAME code path, which removes the v0.1 train/serve skew:

* training   — EMBER2024 JSONL records already contain thrember *raw* features;
               ``vector_from_record`` turns them into vectors with
               ``PEFeatureExtractor.process_raw_features``.
* inference  — ``vector_from_bytes`` runs ``raw_features`` on the file bytes and then the
               same ``process_raw_features``.

thrember is pinned to commit 0ef753e8 (see requirements.lock.txt); FEATURE_VERSION records
it in every model bundle so a version drift is detectable.

Static only: the file is read as bytes and parsed with pefile. Nothing is executed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

FEATURE_VERSION = "ember-v3/thrember@0ef753e8"
FEATURE_DIM = 2568
DEFAULT_MAX_BYTES = 100 * 1024 * 1024

# Metadata keys present in EMBER2024 records that are NOT features (labels, hashes, tags).
METADATA_KEYS = (
    "md5", "sha1", "sha256", "tlsh", "first_submission_date", "last_analysis_date",
    "detection_ratio", "label", "file_type", "family", "family_confidence", "behavior",
    "file_property", "packer", "exploit", "group", "week_id", "caps", "ttps", "mbc",
)


class EmberV3Extractor:
    """Thin, bounded wrapper around thrember.PEFeatureExtractor."""

    def __init__(self, max_bytes: int = DEFAULT_MAX_BYTES):
        from thrember import PEFeatureExtractor

        self._ext = PEFeatureExtractor()
        if self._ext.dim != FEATURE_DIM:
            raise RuntimeError(f"thrember feature dim {self._ext.dim} != expected {FEATURE_DIM}; version drift?")
        self.max_bytes = max_bytes
        self.dim = FEATURE_DIM

    def read_bytes(self, path: str | Path) -> bytes:
        p = Path(path)
        size = p.stat().st_size
        if size > self.max_bytes:
            raise ValueError(f"File size {size} exceeds limit {self.max_bytes}")
        with open(p, "rb") as f:
            return f.read(self.max_bytes)

    def raw_from_bytes(self, bytez: bytes) -> Dict[str, Any]:
        return self._ext.raw_features(bytez)

    def vector_from_raw(self, raw: Dict[str, Any]) -> np.ndarray:
        vec = np.asarray(self._ext.process_raw_features(raw), dtype=np.float32)
        if vec.shape != (FEATURE_DIM,):
            raise ValueError(f"Unexpected vector shape {vec.shape}")
        return vec

    def vector_from_bytes(self, bytez: bytes) -> np.ndarray:
        return self.vector_from_raw(self.raw_from_bytes(bytez))

    def vector_from_file(self, path: str | Path) -> np.ndarray:
        return self.vector_from_bytes(self.read_bytes(path))

    def vector_from_record(self, record: Dict[str, Any] | str) -> np.ndarray:
        """Vectorizes one EMBER2024 JSONL record (dict or raw JSON line)."""
        rec = json.loads(record) if isinstance(record, str) else record
        return self.vector_from_raw(rec)


def record_metadata(record: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts the non-feature metadata (label, family, timestamps, hashes) from a record."""
    return {k: record.get(k) for k in METADATA_KEYS if k in record}


_shared: Optional[EmberV3Extractor] = None


def get_extractor() -> EmberV3Extractor:
    global _shared
    if _shared is None:
        _shared = EmberV3Extractor()
    return _shared
