"""ThreatWeaver Pareto Analysis & Empirical Embedding Dimension Selector.

Implements multi-objective Pareto optimization and configurable utility ranking
to select the optimal embedding dimension strictly based on validation partition metrics.

Locks the optimal dimension, conducts the final untouched chronological test-set evaluation,
and saves the production checkpoint and research selection manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from threatweaver.data.ember_loader import EMBERDatasetLoader
from threatweaver.data.preprocessing import FeatureScaler
from threatweaver.data.splits import TemporalSplitter
from threatweaver.models.calibration import compute_brier_score, compute_ece
from threatweaver.models.classifier import ThreatClassifier, load_checkpoint, save_checkpoint
from threatweaver.models.novelty import NoveltyDetector


# ---------------------------------------------------------------------------
# Configurable Objective Weights
# ---------------------------------------------------------------------------

DEFAULT_SELECTION_WEIGHTS = {
    "macro_f1": 0.30,               # Primary classification metric
    "pr_auc": 0.20,                 # High-imbalance precision/recall capacity
    "detection_rate_at_1pct_fpr": 0.15, # Security threshold performance
    "novelty_auroc": 0.20,          # Out-of-distribution / unfamiliar detection
    "continual_stability": 0.10,    # Resistance to catastrophic forgetting (1 - FT)
    "efficiency_penalty": 0.05,     # Penalty for excessive latency and memory
}


# ---------------------------------------------------------------------------
# Pareto Optimality Analysis
# ---------------------------------------------------------------------------

def compute_pareto_frontier(
    candidates: List[Dict[str, Any]],
) -> Tuple[List[int], List[Dict[str, Any]]]:
    """Identifies Pareto-optimal dimensions across trade-offs.

    Objectives to maximize:
      - macro_f1
      - novelty_auroc
    Objectives to minimize:
      - forgetting
      - latency_ms
      - memory_kb
    """
    pareto_dims: List[int] = []
    frontier_records: List[Dict[str, Any]] = []

    for i, c1 in enumerate(candidates):
        is_dominated = False
        for j, c2 in enumerate(candidates):
            if i == j:
                continue
            # c2 dominates c1 if it is no worse in all and strictly better in at least one
            no_worse = (
                c2["macro_f1"] >= c1["macro_f1"]
                and c2["novelty_auroc"] >= c1["novelty_auroc"]
                and c2["forgetting"] <= c1["forgetting"]
                and c2["latency_ms"] <= c1["latency_ms"]
                and c2["memory_kb"] <= c1["memory_kb"]
            )
            strictly_better = (
                c2["macro_f1"] > c1["macro_f1"]
                or c2["novelty_auroc"] > c1["novelty_auroc"]
                or c2["forgetting"] < c1["forgetting"]
                or c2["latency_ms"] < c1["latency_ms"]
                or c2["memory_kb"] < c1["memory_kb"]
            )
            if no_worse and strictly_better:
                is_dominated = True
                break

        if not is_dominated:
            pareto_dims.append(c1["dim"])
            frontier_records.append(c1)

    return pareto_dims, frontier_records


# ---------------------------------------------------------------------------
# Utility Scoring Function
# ---------------------------------------------------------------------------

def calculate_utility_scores(
    candidates: List[Dict[str, Any]],
    weights: Dict[str, float] = DEFAULT_SELECTION_WEIGHTS,
) -> List[Dict[str, Any]]:
    """Calculates normalized multi-objective utility score for each dimension."""
    def min_max_norm(vals: List[float], higher_is_better: bool = True) -> List[float]:
        min_v = min(vals)
        max_v = max(vals)
        rng = max_v - min_v
        if rng < 1e-12:
            return [1.0 for _ in vals]
        if higher_is_better:
            return [(v - min_v) / rng for v in vals]
        else:
            return [(max_v - v) / rng for v in vals]

    dims = [c["dim"] for c in candidates]
    norm_f1 = min_max_norm([c["macro_f1"] for c in candidates], higher_is_better=True)
    norm_pr = min_max_norm([c["pr_auc"] for c in candidates], higher_is_better=True)
    norm_dr = min_max_norm([c["detection_rate_at_1pct_fpr"] for c in candidates], higher_is_better=True)
    norm_nov = min_max_norm([c["novelty_auroc"] for c in candidates], higher_is_better=True)
    norm_stab = min_max_norm([1.0 - c["forgetting"] for c in candidates], higher_is_better=True)
    norm_eff = min_max_norm([c["latency_ms"] * c["memory_kb"] for c in candidates], higher_is_better=False)

    scored: List[Dict[str, Any]] = []
    for i, c in enumerate(candidates):
        score = (
            weights["macro_f1"] * norm_f1[i]
            + weights["pr_auc"] * norm_pr[i]
            + weights["detection_rate_at_1pct_fpr"] * norm_dr[i]
            + weights["novelty_auroc"] * norm_nov[i]
            + weights["continual_stability"] * norm_stab[i]
            + weights["efficiency_penalty"] * norm_eff[i]
        )
        scored_rec = dict(c)
        scored_rec["utility_score"] = float(score)
        scored_rec["normalized_components"] = {
            "macro_f1": float(norm_f1[i]),
            "pr_auc": float(norm_pr[i]),
            "detection_rate_at_1pct_fpr": float(norm_dr[i]),
            "novelty_auroc": float(norm_nov[i]),
            "continual_stability": float(norm_stab[i]),
            "efficiency": float(norm_eff[i]),
        }
        scored.append(scored_rec)

    scored.sort(key=lambda x: x["utility_score"], reverse=True)
    return scored


# ---------------------------------------------------------------------------
# Final Untouched Chronological Test Evaluation
# ---------------------------------------------------------------------------

def run_untouched_test_evaluation(
    selected_dim: int,
    checkpoint_path: Path,
    data_dir: Path,
) -> Dict[str, Any]:
    """Evaluates the locked selected model strictly ONCE on the untouched chronological test set."""
    print(f"\n[*] Running final evaluation for locked {selected_dim}-D model on UNTOUCHED temporal test set...")

    # Load selected model checkpoint
    model, meta = load_checkpoint(checkpoint_path, device="cpu")
    model.eval()

    # Load EMBER2024 partitions with identical protocol
    from tools.ablation_embedding_dimension import load_ablation_dataset
    X, y, timestamps, X_challenge, y_challenge = load_ablation_dataset(
        data_dir=data_dir,
        win64_quota=3000,
        dotnet_quota=2000,
        challenge_quota=500,
    )

    splitter = TemporalSplitter(train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)
    split = splitter.split_by_timestamps(timestamps)

    X_train_raw = X[split.train_indices]
    y_train = y[split.train_indices]
    X_test_raw = X[split.test_indices]
    y_test = y[split.test_indices]
    ts_test = timestamps[split.test_indices]

    scaler = FeatureScaler.from_dict({
        "fitted": True,
        "mean": meta["feature_mean"],
        "std": meta["feature_std"],
    })
    X_train_scaled = scaler.transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)
    X_chal_scaled = scaler.transform(X_challenge)

    # Classification metrics on untouched test
    X_test_t = torch.tensor(X_test_scaled, dtype=torch.float32)
    with torch.no_grad():
        out = model(X_test_t)
    probs = out.probabilities.numpy()
    preds = np.argmax(probs, axis=-1)
    mal_probs = probs[:, 1]
    test_embs = out.embeddings.numpy()

    fpr_arr, tpr_arr, _ = roc_curve(y_test, mal_probs)
    dr_1pct = float(tpr_arr[np.where(fpr_arr <= 0.01)[0][-1]]) if np.any(fpr_arr <= 0.01) else 0.0
    fpr_95rec = float(fpr_arr[np.where(tpr_arr >= 0.95)[0][0]]) if np.any(tpr_arr >= 0.95) else 1.0

    # Novelty evaluation on test set
    with torch.no_grad():
        train_embs = model(torch.tensor(X_train_scaled, dtype=torch.float32)).embeddings.numpy()
        chal_embs = model(torch.tensor(X_chal_scaled, dtype=torch.float32)).embeddings.numpy()

    detector = NoveltyDetector()
    detector.fit_prototypes(train_embs, y_train, max_prototypes_per_class=12)
    tau = detector.calibrate_threshold(test_embs[y_test == 0], percentile=90.0)

    benign_scores = detector.score(test_embs[y_test == 0])
    chal_scores = detector.score(chal_embs)
    y_nov_true = np.concatenate([np.zeros(len(benign_scores)), np.ones(len(chal_scores))])
    y_nov_scores = np.concatenate([benign_scores, chal_scores])
    novelty_auroc = float(roc_auc_score(y_nov_true, y_nov_scores))

    test_metrics = {
        "dataset_split": "Untouched Future Test Split (15% Chronological)",
        "num_test_samples": int(len(y_test)),
        "timestamps_range": [int(ts_test.min()), int(ts_test.max())],
        "macro_f1": float(f1_score(y_test, preds, average="macro")),
        "binary_f1": float(f1_score(y_test, preds, zero_division=0)),
        "accuracy": float(accuracy_score(y_test, preds)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, preds)),
        "precision": float(precision_score(y_test, preds, zero_division=0)),
        "recall": float(recall_score(y_test, preds, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, mal_probs)),
        "pr_auc": float(average_precision_score(y_test, mal_probs)),
        "detection_rate_at_1pct_fpr": dr_1pct,
        "fpr_at_95pct_recall": fpr_95rec,
        "brier_score": compute_brier_score(mal_probs, y_test),
        "ece": compute_ece(probs, y_test),
        "novelty_auroc": novelty_auroc,
        "novelty_threshold_tau": float(tau),
        "benign_novelty_fpr": float(np.mean(benign_scores > tau)),
        "challenge_novelty_detection": float(np.mean(chal_scores > tau)),
    }

    return test_metrics


# ---------------------------------------------------------------------------
# Main Selector Routine
# ---------------------------------------------------------------------------

def select_best_dimension(
    results_json_path: Path,
    data_dir: Path,
    output_dir: Path,
    checkpoints_dir: Path,
    weights: Dict[str, float] = DEFAULT_SELECTION_WEIGHTS,
) -> Dict[str, Any]:
    """Analyzes validation results, performs Pareto optimization, and locks optimal dimension."""
    if not results_json_path.is_file():
        raise FileNotFoundError(f"Ablation results JSON not found at: {results_json_path}")

    with open(results_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    agg_results = data["aggregated_results"]
    cl_results = data.get("cl_results", {})

    candidates: List[Dict[str, Any]] = []
    for dim_str, agg in agg_results.items():
        dim = int(dim_str)
        # Continual forgetting under uncertainty diversity or uncertainty
        cl_entry = cl_results.get(dim_str, {})
        best_cl = cl_entry.get("uncertainty_diversity", cl_entry.get("uncertainty", {}))
        forgetting = float(best_cl.get("catastrophic_forgetting", 0.15))

        candidates.append({
            "dim": dim,
            "macro_f1": float(agg["macro_f1"]["mean"]),
            "macro_f1_std": float(agg["macro_f1"]["std"]),
            "pr_auc": float(agg["pr_auc"]["mean"]),
            "detection_rate_at_1pct_fpr": float(agg["detection_rate_at_1pct_fpr"]["mean"]),
            "novelty_auroc": float(agg["novelty_auroc"]["mean"]),
            "forgetting": forgetting,
            "latency_ms": float(agg["inference_latency_ms"]["mean"]),
            "memory_kb": float(agg["estimated_memory_kb"]["mean"]),
            "brier_score": float(agg["brier_score"]["mean"]),
            "ece": float(agg["ece"]["mean"]),
        })

    # 1. Pareto Frontier Analysis
    pareto_dims, pareto_frontier = compute_pareto_frontier(candidates)

    # 2. Multi-Attribute Utility Ranking
    scored_candidates = calculate_utility_scores(candidates, weights)
    best_candidate = scored_candidates[0]
    best_dim = int(best_candidate["dim"])

    print("\n" + "=" * 70)
    print("EMBEDDING DIMENSION SELECTION ANALYSIS")
    print("=" * 70)
    print(f"Objective Weights Configured: {weights}")
    print(f"Pareto Frontier Dimensions: {[f'{d}D' for d in pareto_dims]}")

    print("\nCandidate Rankings by Multi-Attribute Utility Score:")
    for rank, sc in enumerate(scored_candidates, 1):
        is_pareto = " [PARETO OPTIMAL]" if sc["dim"] in pareto_dims else ""
        print(f"  #{rank}: {sc['dim']:>3}-D | Utility Score: {sc['utility_score']:.4f} | Macro-F1: {sc['macro_f1']:.4f} | Novelty AUROC: {sc['novelty_auroc']:.4f} | Latency: {sc['latency_ms']:.3f}ms{is_pareto}")

    print(f"\n[SELECTED] LOCKED BEST EMBEDDING DIMENSION: {best_dim}-D")

    # 3. Untouched Test Set Evaluation
    ckpt_path = checkpoints_dir / f"threatweaver_{best_dim}d.pt"
    test_metrics = run_untouched_test_evaluation(best_dim, ckpt_path, data_dir)

    print("\n--- FINAL UNTOUCHED TEMPORAL TEST RESULTS (RESEARCH SPEC) ---")
    print(f"Macro-F1:                  {test_metrics['macro_f1']:.4f}")
    print(f"ROC-AUC:                   {test_metrics['roc_auc']:.4f}")
    print(f"PR-AUC:                    {test_metrics['pr_auc']:.4f}")
    print(f"Detection Rate @ 1% FPR:   {test_metrics['detection_rate_at_1pct_fpr']:.4f}")
    print(f"FPR @ 95% Recall:          {test_metrics['fpr_at_95pct_recall']:.4f}")
    print(f"Brier Calibration Score:   {test_metrics['brier_score']:.4f}")
    print(f"Expected Calib Error (ECE):{test_metrics['ece']:.4f}")
    print(f"Novelty AUROC (vs Chal):   {test_metrics['novelty_auroc']:.4f}")
    print(f"Calibrated Threshold tau:  {test_metrics['novelty_threshold_tau']:.4f}")
    print(f"Benign Novelty FPR:        {test_metrics['benign_novelty_fpr']:.4f}")
    print(f"Malware Novelty Detection: {test_metrics['challenge_novelty_detection']:.4f}")

    # 4. Link & Update Production Checkpoint
    prod_ckpt = checkpoints_dir / "threatweaver_v1.pt"
    if ckpt_path.is_file():
        shutil.copyfile(ckpt_path, prod_ckpt)
        sig_src = ckpt_path.with_suffix(".pt.sig")
        sig_dst = prod_ckpt.with_suffix(".pt.sig")
        if sig_src.is_file():
            shutil.copyfile(sig_src, sig_dst)
        print(f"\n[+] Updated production checkpoint '{prod_ckpt.name}' to locked {best_dim}-D architecture.")

    # 5. Export Selection Manifest
    manifest = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "selected_best_dimension": best_dim,
        "pareto_frontier_dimensions": pareto_dims,
        "selection_weights": weights,
        "scored_rankings": scored_candidates,
        "best_candidate_validation_summary": best_candidate,
        "final_untouched_test_results": test_metrics,
        "production_checkpoint": str(prod_ckpt),
    }

    manifest_path = output_dir / "selected_embedding_dimension.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Saved dimension selection report to: {manifest_path}")

    return manifest


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatWeaver Pareto Analysis & Dimension Selector")
    parser.add_argument("--results-json", default="artifacts/benchmarks/embedding_dimension_results.json", help="Path to ablation results JSON")
    parser.add_argument("--data-dir", default="data/ember2024", help="Path to EMBER2024 dataset root")
    parser.add_argument("--output-dir", default="artifacts/benchmarks", help="Output directory")
    parser.add_argument("--checkpoints-dir", default="artifacts/checkpoints", help="Checkpoints directory")

    args = parser.parse_args()
    select_best_dimension(
        results_json_path=Path(args.results_json),
        data_dir=Path(args.data_dir),
        output_dir=Path(args.output_dir),
        checkpoints_dir=Path(args.checkpoints_dir),
    )


if __name__ == "__main__":
    main()
