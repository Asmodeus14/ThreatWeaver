"""Evaluation harness: the single source of truth for every reported number.

Produces ``eval.json`` (schema ``eval/1``). README tables, the model card and UI charts
must be generated from this file, never hand-copied.

Conventions
* scores are P(malicious) in [0, 1]; labels 1 = malicious, 0 = benign.
* operating thresholds are chosen on VALIDATION data for a target FPR and then applied,
  unchanged, to test data; the realised test FPR is reported next to the target.
* every headline metric carries a bootstrap 95% CI.
* provenance (dataset manifest hash, split definition, code commit, model id) is embedded,
  and ``kind`` distinguishes benchmark / operational_sanity / synthetic results.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

SCHEMA = "eval/1"
VALID_KINDS = ("benchmark", "operational_sanity", "synthetic")


# ------------------------------------------------------------------ primitives

def threshold_for_fpr(y_true: np.ndarray, scores: np.ndarray, target_fpr: float) -> float:
    """Smallest threshold whose FPR on these (validation) samples is <= target_fpr."""
    benign = np.sort(scores[y_true == 0])
    if benign.size == 0:
        raise ValueError("No benign samples to calibrate an FPR threshold.")
    k = int(np.floor(target_fpr * benign.size))  # number of benign allowed above threshold
    if k <= 0:
        return float(np.nextafter(benign[-1], np.inf))
    return float(benign[benign.size - k])


def rates_at_threshold(y_true: np.ndarray, scores: np.ndarray, thr: float) -> Dict[str, Any]:
    pred = scores >= thr
    tp = int(np.sum(pred & (y_true == 1)))
    fp = int(np.sum(pred & (y_true == 0)))
    tn = int(np.sum(~pred & (y_true == 0)))
    fn = int(np.sum(~pred & (y_true == 1)))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec_b = tn / (tn + fn) if tn + fn else 0.0
    rec_b = tn / (tn + fp) if tn + fp else 0.0
    f1_m = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    f1_b = 2 * prec_b * rec_b / (prec_b + rec_b) if prec_b + rec_b else 0.0
    return {
        "threshold": float(thr),
        "tpr": rec, "fpr": fp / (fp + tn) if fp + tn else 0.0, "fnr": fn / (fn + tp) if fn + tp else 0.0,
        "precision": prec, "recall": rec, "macro_f1": (f1_m + f1_b) / 2,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def tpr_at_fpr(y_true: np.ndarray, scores: np.ndarray, target_fpr: float) -> float:
    """Detection rate at a target FPR measured on the SAME data (curve read-off)."""
    fpr, tpr, _ = roc_curve(y_true, scores)
    ok = fpr <= target_fpr
    return float(tpr[ok].max()) if ok.any() else 0.0


def fpr_at_recall(y_true: np.ndarray, scores: np.ndarray, recall: float = 0.95) -> float:
    fpr, tpr, _ = roc_curve(y_true, scores)
    ok = tpr >= recall
    return float(fpr[ok].min()) if ok.any() else 1.0


def expected_calibration_error(y_true: np.ndarray, scores: np.ndarray, n_bins: int = 15) -> Dict[str, Any]:
    """ECE on P(malicious) with equal-width bins; also returns the reliability-diagram data."""
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(scores, edges[1:-1], right=True), 0, n_bins - 1)
    ece, bins = 0.0, []
    for b in range(n_bins):
        m = idx == b
        if not m.any():
            continue
        conf, acc = float(scores[m].mean()), float(y_true[m].mean())
        ece += m.mean() * abs(acc - conf)
        bins.append({"lo": float(edges[b]), "hi": float(edges[b + 1]), "count": int(m.sum()),
                     "mean_score": conf, "fraction_malicious": acc})
    return {"ece": float(ece), "bins": bins}


def _downsample_curve(x: np.ndarray, y: np.ndarray, t: np.ndarray, max_points: int = 400) -> Dict[str, List[float]]:
    if len(x) > max_points:
        keep = np.unique(np.linspace(0, len(x) - 1, max_points).astype(int))
        x, y, t = x[keep], y[keep], t[keep]
    return {"x": [float(v) for v in x], "y": [float(v) for v in y], "thresholds": [float(v) for v in t]}


def bootstrap_ci(fn, y_true, scores, n_boot: int = 200, seed: int = 0, stratified: bool = True):
    rng = np.random.default_rng(seed)
    pos, neg = np.flatnonzero(y_true == 1), np.flatnonzero(y_true == 0)
    vals = []
    for _ in range(n_boot):
        if stratified:
            idx = np.concatenate([rng.choice(pos, pos.size), rng.choice(neg, neg.size)])
        else:
            idx = rng.integers(0, y_true.size, y_true.size)
        try:
            vals.append(fn(y_true[idx], scores[idx]))
        except ValueError:
            continue
    if not vals:
        return None
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return {"lo": float(lo), "hi": float(hi), "n_boot": len(vals)}


# ------------------------------------------------------------------ reports

def binary_report(
    y_true: Sequence[int],
    scores: Sequence[float],
    thresholds: Optional[Dict[str, float]] = None,
    fpr_targets: Iterable[float] = (0.001, 0.01),
    n_boot: int = 200,
    seed: int = 0,
) -> Dict[str, Any]:
    """Full metric set for one split. `thresholds` (e.g. from validation) are applied as-is."""
    y = np.asarray(y_true).astype(int)
    s = np.asarray(scores, dtype=np.float64)
    if y.size != s.size or y.size == 0:
        raise ValueError("labels and scores must be non-empty and the same length")
    report: Dict[str, Any] = {
        "n": int(y.size), "n_malicious": int(y.sum()), "n_benign": int((y == 0).sum()),
    }
    both = report["n_malicious"] > 0 and report["n_benign"] > 0
    if both:
        report["roc_auc"] = float(roc_auc_score(y, s))
        report["pr_auc"] = float(average_precision_score(y, s))
        report["fpr_at_95_recall"] = fpr_at_recall(y, s, 0.95)
        report["tpr_at_fpr_curve"] = {f"{t:g}": tpr_at_fpr(y, s, t) for t in fpr_targets}
        report["ci95"] = {
            "roc_auc": bootstrap_ci(roc_auc_score, y, s, n_boot, seed),
            "pr_auc": bootstrap_ci(average_precision_score, y, s, n_boot, seed),
            **{f"tpr_at_fpr_{t:g}": bootstrap_ci(lambda a, b, t=t: tpr_at_fpr(a, b, t), y, s, n_boot, seed)
               for t in fpr_targets},
        }
        fpr, tpr, thr = roc_curve(y, s)
        report["roc_curve"] = _downsample_curve(fpr, tpr, np.clip(thr, 0, 1))
        from sklearn.metrics import precision_recall_curve
        p, r, t = precision_recall_curve(y, s)
        report["pr_curve"] = _downsample_curve(r[:-1], p[:-1], t)
    cal = expected_calibration_error(y, s)
    report["ece"] = cal["ece"]
    report["reliability"] = cal["bins"]
    report["brier"] = float(np.mean((s - y) ** 2))
    report["score_histogram"] = {
        "edges": [float(e) for e in np.linspace(0, 1, 21)],
        "benign": np.histogram(s[y == 0], bins=20, range=(0, 1))[0].tolist(),
        "malicious": np.histogram(s[y == 1], bins=20, range=(0, 1))[0].tolist(),
    }
    report["operating_points"] = {name: rates_at_threshold(y, s, thr) for name, thr in (thresholds or {}).items()}
    return report


def novelty_report(in_dist_scores: Sequence[float], ood_scores: Sequence[float]) -> Dict[str, Any]:
    """Novelty scores (higher = more unfamiliar): in-distribution vs out-of-distribution samples."""
    a = np.asarray(in_dist_scores, dtype=np.float64)
    b = np.asarray(ood_scores, dtype=np.float64)
    y = np.concatenate([np.zeros(a.size), np.ones(b.size)]).astype(int)
    s = np.concatenate([a, b])
    return {
        "n_in": int(a.size), "n_ood": int(b.size),
        "auroc": float(roc_auc_score(y, s)),
        "fpr_at_95_tpr": fpr_at_recall(y, s, 0.95),
        "ci95_auroc": bootstrap_ci(roc_auc_score, y, s),
    }


def drift_report(
    y_true: Sequence[int], scores: Sequence[float], timestamps: Sequence[int],
    threshold: float, period_days: int = 14,
) -> List[Dict[str, Any]]:
    """Per-period metrics at a fixed threshold (TESSERACT-style time-aware evaluation)."""
    y, s, t = np.asarray(y_true).astype(int), np.asarray(scores, float), np.asarray(timestamps, np.int64)
    if t.size == 0:
        return []
    start, out = int(t.min()), []
    span = period_days * 86400
    for lo in range(start, int(t.max()) + 1, span):
        m = (t >= lo) & (t < lo + span)
        if m.sum() < 20:
            continue
        r = rates_at_threshold(y[m], s[m], threshold)
        row = {"period_start": time.strftime("%Y-%m-%d", time.gmtime(lo)), "n": int(m.sum()),
               "tpr": r["tpr"], "fpr": r["fpr"], "macro_f1": r["macro_f1"]}
        if 0 < y[m].sum() < m.sum():
            row["roc_auc"] = float(roc_auc_score(y[m], s[m]))
        out.append(row)
    return out


# ------------------------------------------------------------------ provenance / output

def git_commit(repo: Path = Path(".")) -> Optional[str]:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, timeout=10)
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo,
                               capture_output=True, text=True, timeout=10).stdout.strip()
        return out.stdout.strip() + ("+dirty" if dirty else "") if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_eval(
    out_path: Path,
    *,
    kind: str,
    model: Dict[str, Any],
    dataset: Dict[str, Any],
    splits: Dict[str, Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if kind not in VALID_KINDS:
        raise ValueError(f"kind must be one of {VALID_KINDS}")
    payload = {
        "schema": SCHEMA,
        "kind": kind,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "code_commit": git_commit(),
        "model": model,
        "dataset": dataset,
        "splits": splits,
        **(extra or {}),
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
