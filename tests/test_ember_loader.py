"""Tests for EMBER dataset loader, memmap adapter, and live PE extractor."""

from pathlib import Path
import numpy as np
import pytest

from threatweaver.data.ember_loader import (
    EMBERDatasetLoader,
    generate_synthetic_ember_jsonl,
    EMBER_RAW_FEATURE_DIM,
)
from threatweaver.scanner.feature_extractor import FEATURE_DIM
from tests.fixtures import create_minimal_pe


def test_synthetic_ember_generation_and_streaming(tmp_path: Path):
    """Validates streaming reader, chunking, and label filtering on EMBER JSONL."""
    jsonl_path = tmp_path / "ember_test.jsonl"
    generate_synthetic_ember_jsonl(jsonl_path, num_samples=100, seed=42)

    loader = EMBERDatasetLoader(schema_mode="harmonized", drop_unlabeled=True)
    chunks = list(loader.stream_jsonl(jsonl_path, chunk_size=20))

    assert len(chunks) > 0
    total_samples = sum(len(c["labels"]) for c in chunks)
    assert total_samples <= 100

    # Verify no -1 labels present
    for c in chunks:
        assert np.all(c["labels"] >= 0)
        assert c["features"].shape[1] == FEATURE_DIM
        assert np.all(np.isfinite(c["features"]))


def test_ember_native_schema_streaming(tmp_path: Path):
    """Validates native 2381-dim feature extraction mode."""
    jsonl_path = tmp_path / "ember_native.jsonl"
    generate_synthetic_ember_jsonl(jsonl_path, num_samples=25, seed=42)

    loader = EMBERDatasetLoader(schema_mode="native", drop_unlabeled=True)
    chunks = list(loader.stream_jsonl(jsonl_path, chunk_size=25))

    assert len(chunks) > 0
    first_chunk = chunks[0]
    assert first_chunk["features"].shape[1] == EMBER_RAW_FEATURE_DIM
