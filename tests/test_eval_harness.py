"""Evaluation harness correctness against hand-computed values and sklearn."""

import json

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from threatweaver.evaluation.harness import (
    binary_report, drift_report, expected_calibration_error, novelty_report,
    rates_at_threshold, threshold_for_fpr, tpr_at_fpr, write_eval,
)


def test_rates_at_threshold_hand_computed():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    s = np.array([0.1, 0.2, 0.6, 0.3, 0.7, 0.8, 0.4, 0.9])
    r = rates_at_threshold(y, s, 0.5)
    assert r["confusion"] == {"tp": 3, "fp": 1, "tn": 3, "fn": 1}
    assert r["tpr"] == 0.75 and r["fpr"] == 0.25 and r["precision"] == 0.75


def test_threshold_for_fpr_respects_target_on_calibration_data():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(10000), np.ones(1000)].astype(int)
    s = np.r_[rng.beta(2, 8, 10000), rng.beta(8, 2, 1000)]
    for target in (0.001, 0.01, 0.05):
        thr = threshold_for_fpr(y, s, target)
        assert rates_at_threshold(y, s, thr)["fpr"] <= target


def test_tpr_at_fpr_perfect_and_random():
    y = np.r_[np.zeros(500), np.ones(500)].astype(int)
    assert tpr_at_fpr(y, np.r_[np.zeros(500), np.ones(500)], 0.01) == 1.0
    rng = np.random.default_rng(1)
    assert tpr_at_fpr(y, rng.random(1000), 0.01) < 0.1


def test_binary_report_matches_sklearn_and_has_cis():
    rng = np.random.default_rng(2)
    y = np.r_[np.zeros(800), np.ones(400)].astype(int)
    s = np.clip(np.r_[rng.normal(0.3, 0.15, 800), rng.normal(0.7, 0.15, 400)], 0, 1)
    rep = binary_report(y, s, thresholds={"t50": 0.5}, n_boot=50)
    assert rep["roc_auc"] == pytest.approx(roc_auc_score(y, s))
    ci = rep["ci95"]["roc_auc"]
    assert ci["lo"] <= rep["roc_auc"] <= ci["hi"]
    assert rep["operating_points"]["t50"]["threshold"] == 0.5
    assert sum(rep["score_histogram"]["benign"]) == 800
    assert len(rep["roc_curve"]["x"]) <= 400
    json.dumps(rep)  # serializable


def test_ece_zero_for_perfectly_calibrated_bins():
    s = np.repeat([0.1, 0.9], 1000)
    y = np.r_[np.r_[np.ones(100), np.zeros(900)], np.r_[np.ones(900), np.zeros(100)]].astype(int)
    assert expected_calibration_error(y, s)["ece"] == pytest.approx(0.0, abs=1e-9)


def test_novelty_report_separation():
    rng = np.random.default_rng(3)
    r = novelty_report(rng.normal(0, 1, 500), rng.normal(3, 1, 500))
    assert r["auroc"] > 0.95


def test_drift_report_periods():
    rng = np.random.default_rng(4)
    t = np.sort(rng.integers(1_700_000_000, 1_700_000_000 + 60 * 86400, 2000))
    y = rng.integers(0, 2, 2000)
    s = np.clip(y * 0.6 + rng.random(2000) * 0.4, 0, 1)
    rows = drift_report(y, s, t, threshold=0.5, period_days=14)
    assert 4 <= len(rows) <= 5 and all("tpr" in r for r in rows)


def test_write_eval_requires_valid_kind(tmp_path):
    with pytest.raises(ValueError):
        write_eval(tmp_path / "e.json", kind="marketing", model={}, dataset={}, splits={})
    p = write_eval(tmp_path / "e.json", kind="benchmark", model={"id": "m"}, dataset={"manifest_sha256": "x"}, splits={})
    assert p["schema"] == "eval/1" and json.loads((tmp_path / "e.json").read_text())["kind"] == "benchmark"
