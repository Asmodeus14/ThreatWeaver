"""Tests for static feature extraction engine."""

import numpy as np
from pathlib import Path

from threatweaver.scanner.feature_extractor import (
    FeatureExtractor,
    FEATURE_DIM,
    SCHEMA_VERSION,
)
from tests.fixtures import create_minimal_pe


def test_feature_extraction_dimension_and_bounds(tmp_path: Path):
    """Validates that extracted features match the 256-dim schema and are bounded."""
    pe_file = create_minimal_pe(tmp_path / "valid.exe", is_64bit=True)
    extractor = FeatureExtractor()
    features = extractor.extract_from_file(pe_file)

    assert features.schema_version == SCHEMA_VERSION
    assert features.is_valid_pe is True
    assert isinstance(features.feature_vector, np.ndarray)
    assert features.feature_vector.shape == (FEATURE_DIM,)
    assert features.feature_vector.dtype == np.float32

    # Check that values are finite and within reasonable bounds [-10, 10]
    assert np.all(np.isfinite(features.feature_vector))
    assert np.all(features.feature_vector >= 0.0)
    assert np.all(features.feature_vector <= 10.0)


def test_feature_extraction_on_invalid_file(tmp_path: Path):
    """Extracts zeroed vector with invalid indicator on non-PE files."""
    text_file = tmp_path / "readme.txt"
    text_file.write_text("Hello ThreatWeaver", encoding="utf-8")

    extractor = FeatureExtractor()
    features = extractor.extract_from_file(text_file)

    assert features.is_valid_pe is False
    assert features.feature_vector.shape == (FEATURE_DIM,)
    assert np.all(features.feature_vector == 0.0)
    assert len(features.detected_indicators) > 0


def test_wx_indicator_detection(tmp_path: Path):
    """Checks that W^X section generates an alert indicator and non-zero feature."""
    pe_file = create_minimal_pe(
        tmp_path / "wx.exe", is_64bit=True, writable_and_executable=True
    )
    extractor = FeatureExtractor()
    features = extractor.extract_from_file(pe_file)

    assert features.is_valid_pe is True
    # Dim 38 is count_wx_sections
    assert features.feature_vector[38] > 0.0
    assert any("W^X violation" in ind for ind in features.detected_indicators)
