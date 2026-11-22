"""Model regression gate behaviour."""

import copy
import json
from pathlib import Path

import pytest

from threatweaver.evaluation.gate import compare, compare_files

REPO = Path(__file__).resolve().parent.parent
LGBM = REPO / "artifacts" / "models" / "lgbm-v3-dotnet" / "eval.json"
LEGACY = REPO / "artifacts" / "eval" / "legacy-v0.1-128d" / "eval.json"


def _base():
    return {
        "dataset": {"manifest_sha256": "abc"},
        "splits": {
            "test": {"tpr_at_fpr_curve": {"0.01": 0.95, "0.001": 0.83},
                     "operating_points": {"tau_low_fpr_1pct": {"fpr": 0.0099}}},
            "challenge": {"detection_at": {"tau_low_fpr_1pct": 0.79}},
        },
    }


def test_identical_model_passes():
    assert compare(_base(), _base()).passed


def test_small_noise_within_tolerance_passes():
    c = copy.deepcopy(_base())
    c["splits"]["test"]["tpr_at_fpr_curve"]["0.01"] = 0.945
    assert compare(c, _base()).passed


def test_detection_drop_fails():
    c = copy.deepcopy(_base())
    c["splits"]["test"]["tpr_at_fpr_curve"]["0.01"] = 0.93
    r = compare(c, _base())
    assert not r.passed and "tpr_at_1pct_fpr" in r.reason


def test_fpr_rise_fails():
    c = copy.deepcopy(_base())
    c["splits"]["test"]["operating_points"]["tau_low_fpr_1pct"]["fpr"] = 0.012
    assert not compare(c, _base()).passed


def test_different_test_data_is_not_comparable():
    c = copy.deepcopy(_base())
    c["dataset"]["manifest_sha256"] = "other"
    r = compare(c, _base())
    assert not r.passed and not r.comparable


def test_real_artifacts():
    if not (LGBM.is_file() and LEGACY.is_file()):
        pytest.skip("artifacts missing")
    assert compare_files(LGBM, LGBM).passed
    assert not compare_files(LEGACY, LGBM).comparable  # different test splits: refused, not silently compared
