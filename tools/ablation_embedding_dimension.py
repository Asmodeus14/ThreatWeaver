"""ThreatWeaver Empirical Embedding Dimension Ablation Study Engine.

Systematically trains and evaluates ThreatWeaver ResMLP architectures across candidate
embedding dimensions (32, 64, 96, 128, 192, 256) under strict experimental control.

Evaluates:
1. Classification performance (Macro-F1, ROC-AUC, PR-AUC, DR@1%FPR, FPR@95%Recall)
2. Calibrated uncertainty (Brier score, Expected Calibration Error)
3. Embedding-space novelty detection (AUROC, OOD separation, benign FPR, distance distributions)
4. Continual-learning adaptation & catastrophic forgetting across T1..T5
5. Computational efficiency (inference latency, throughput, memory, checkpoint size)
6. Multi-seed statistical variance (mean, std, min, max across seeds 42, 1337, 2026)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
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
from threatweaver.learning.trainer import ContinualTrainer
from threatweaver.models.calibration import calibrate_temperature, compute_brier_score, compute_ece
from threatweaver.models.classifier import ThreatClassifier, load_checkpoint, save_checkpoint
from threatweaver.models.novelty import NoveltyDetector

# Optimize CPU parallelism
if torch.get_num_threads() < 4:
    torch.set_num_threads(min(8, os.cpu_count() or 4))


# ---------------------------------------------------------------------------
# Metric Helper Functions
# ---------------------------------------------------------------------------

def compute_detection_rate_at_fpr(y_true: np.ndarray, y_scores: np.ndarray, target_fpr: float = 0.01) -> float:
    """Computes True Positive Rate (Detection Rate) at a fixed False Positive Rate (e.g. 1%)."""
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    valid_idx = np.where(fpr <= target_fpr)[0]
    if len(valid_idx) == 0:
        return 0.0
    return float(tpr[valid_idx[-1]])


def compute_fpr_at_recall(y_true: np.ndarray, y_scores: np.ndarray, target_recall: float = 0.95) -> float:
    """Computes False Positive Rate at a required Detection Rate (e.g. 95%)."""
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    valid_idx = np.where(tpr >= target_recall)[0]
    if len(valid_idx) == 0:
        return 1.0
    return float(fpr[valid_idx[0]])


# ---------------------------------------------------------------------------
# Data Loading & Chronological Partitioning
# ---------------------------------------------------------------------------

def load_ablation_dataset(
    data_dir: Path,
    win64_quota: int = 3000,
    dotnet_quota: int = 2000,
    challenge_quota: int = 500,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Loads balanced samples from real EMBER2024 partitions with chronological timestamps.

    Returns:
        (X, y, timestamps, X_challenge, y_challenge)
    """
    loader = EMBERDatasetLoader(schema_mode="harmonized")

    # 1. Load Win64_test samples
    w64_files = sorted(list((data_dir / "Win64_test").glob("*.jsonl")))
    w64_b_target = win64_quota // 2
    w64_m_target = win64_quota // 2
    w64_feats, w64_labels, w64_ts = _extract_records_from_files(w64_files, loader, w64_b_target, w64_m_target)
    print(f"  [+] Loaded Win64 partition: {len(w64_labels)} samples ({w64_labels.count(0)} benign, {w64_labels.count(1)} malware)")

    # 2. Load Dot_Net_test samples
    dnet_files = sorted(list((data_dir / "Dot_Net_test").glob("*.jsonl")))
    dnet_b_target = dotnet_quota // 2
    dnet_m_target = dotnet_quota // 2
    dnet_feats, dnet_labels, dnet_ts = _extract_records_from_files(dnet_files, loader, dnet_b_target, dnet_m_target)
    print(f"  [+] Loaded Dot_Net partition: {len(dnet_labels)} samples ({dnet_labels.count(0)} benign, {dnet_labels.count(1)} malware)")

    # 3. Load challenge evasive malware samples for novelty testing
    chal_files = sorted(list((data_dir / "challenge").glob("*.jsonl")))
    chal_feats: List[np.ndarray] = []
    chal_labels: List[int] = []
    for cf in chal_files:
        if len(chal_feats) >= challenge_quota:
            break
        with open(cf, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(chal_feats) >= challenge_quota:
                    break
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("label") == 1:
                        chal_feats.append(loader.harmonize_ember_record(rec))
                        chal_labels.append(1)
                except Exception:
                    continue
    print(f"  [+] Loaded Challenge partition (OOD evasive malware): {len(chal_labels)} samples")

    # Merge base partitions
    all_feats = w64_feats + dnet_feats
    all_labels = w64_labels + dnet_labels
    all_ts = w64_ts + dnet_ts

    X = np.array(all_feats, dtype=np.float32)
    y = np.array(all_labels, dtype=np.int64)
    timestamps = np.array(all_ts, dtype=np.int64)

    X_challenge = np.array(chal_feats, dtype=np.float32)
    y_challenge = np.array(chal_labels, dtype=np.int64)

    return X, y, timestamps, X_challenge, y_challenge


def _extract_records_from_files(
    files: List[Path],
    loader: EMBERDatasetLoader,
    target_benign: int,
    target_malware: int,
) -> Tuple[List[np.ndarray], List[int], List[int]]:
    feats: List[np.ndarray] = []
    labels: List[int] = []
    ts: List[int] = []
    b_cnt, m_cnt = 0, 0

    for file_path in files:
        if b_cnt >= target_benign and m_cnt >= target_malware:
            break
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    lbl = rec.get("label", -1)
                    timestamp = int(rec.get("first_submission_date") or rec.get("appeared") or 0)
                    if lbl == 0 and b_cnt < target_benign:
                        feats.append(loader.harmonize_ember_record(rec))
                        labels.append(0)
                        ts.append(timestamp)
                        b_cnt += 1
                    elif lbl == 1 and m_cnt < target_malware:
                        feats.append(loader.harmonize_ember_record(rec))
                        labels.append(1)
                        ts.append(timestamp)
                        m_cnt += 1
                    if b_cnt >= target_benign and m_cnt >= target_malware:
                        break
                except Exception:
                    continue
    return feats, labels, ts


# ---------------------------------------------------------------------------
# Model Training Routine (Strict Experimental Control)
# ---------------------------------------------------------------------------

def train_ablation_model(
    embedding_dim: int,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    seed: int = 42,
    epochs: int = 20,
    batch_size: int = 64,
    lr: float = 1e-3,
    label_smoothing: float = 0.05,
) -> Tuple[ThreatClassifier, float, float]:
    """Trains ThreatClassifier with identical hyperparameters, varying only embedding_dim."""
    torch.manual_seed(seed)
    np.random.seed(seed)

    model = ThreatClassifier(
        input_dim=256,
        hidden_dims=[256, 128],
        embedding_dim=embedding_dim,
        num_classes=2,
        dropout=0.2,
        temperature=1.0,
        head_input="embedding",
    )

    criterion = nn.CrossEntropyLoss(label_smoothing=label_smoothing)
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)

    X_train_t = torch.tensor(X_train, dtype=torch.float32)
    y_train_t = torch.tensor(y_train, dtype=torch.long)
    dataset = torch.utils.data.TensorDataset(X_train_t, y_train_t)
    dataloader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

    t0 = time.time()
    for _ in range(epochs):
        model.train()
        for bx, by in dataloader:
            optimizer.zero_grad()
            out = model(bx)
            loss = criterion(out.logits, by)
            loss.backward()
            optimizer.step()
        scheduler.step()
    train_time_sec = time.time() - t0

    # Calibrate temperature on validation split
    model.eval()
    with torch.no_grad():
        val_out = model(torch.tensor(X_val, dtype=torch.float32))
        calibrated_temp = calibrate_temperature(val_out.logits, y_val)
    model.temperature = calibrated_temp

    return model, train_time_sec, calibrated_temp


# ---------------------------------------------------------------------------
# Metric Evaluation Routine
# ---------------------------------------------------------------------------

def evaluate_ablation_run(
    model: ThreatClassifier,
    scaler: FeatureScaler,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_challenge: np.ndarray,
    y_challenge: np.ndarray,
    embedding_dim: int,
    seed: int,
    train_time_sec: float,
    calibrated_temp: float,
) -> Dict[str, Any]:
    """Evaluates classification, calibration, novelty detection, and efficiency metrics."""
    model.eval()
    X_val_t = torch.tensor(X_val, dtype=torch.float32)

    # 1. Efficiency: Latency & Throughput Benchmark
    warmup_n = min(100, len(X_val))
    with torch.no_grad():
        for _ in range(3):
            _ = model(X_val_t[:warmup_n])

    t_eval_start = time.perf_counter()
    with torch.no_grad():
        val_out = model(X_val_t)
    total_eval_time = time.perf_counter() - t_eval_start
    latency_ms_per_sample = (total_eval_time / len(X_val)) * 1000.0
    throughput_samples_per_sec = len(X_val) / total_eval_time if total_eval_time > 0 else 0.0

    probs = val_out.probabilities.numpy()
    preds = np.argmax(probs, axis=-1)
    mal_probs = probs[:, 1]
    val_embs = val_out.embeddings.numpy()

    # Parameter count and memory estimation
    param_count = sum(p.numel() for p in model.parameters())
    memory_kb = (param_count * 4) / 1024.0

    # 2. Classification Metrics (on Validation Split)
    acc = float(accuracy_score(y_val, preds))
    bal_acc = float(balanced_accuracy_score(y_val, preds))
    prec = float(precision_score(y_val, preds, zero_division=0))
    rec = float(recall_score(y_val, preds, zero_division=0))
    macro_f1 = float(f1_score(y_val, preds, average="macro"))
    binary_f1 = float(f1_score(y_val, preds, zero_division=0))
    roc_auc = float(roc_auc_score(y_val, mal_probs))
    pr_auc = float(average_precision_score(y_val, mal_probs))
    dr_at_1pct_fpr = compute_detection_rate_at_fpr(y_val, mal_probs, 0.01)
    fpr_at_95pct_recall = compute_fpr_at_recall(y_val, mal_probs, 0.95)

    # 3. Calibration Metrics
    brier = compute_brier_score(mal_probs, y_val)
    ece = compute_ece(probs, y_val, n_bins=10)

    # 4. Novelty Detection Evaluation
    # Fit prototypes on training set embeddings
    with torch.no_grad():
        train_out = model(torch.tensor(X_train, dtype=torch.float32))
        train_embs = train_out.embeddings.numpy()
        chal_out = model(torch.tensor(X_challenge, dtype=torch.float32))
        chal_embs = chal_out.embeddings.numpy()

    detector = NoveltyDetector(distance_metric="cosine")
    detector.fit_prototypes(train_embs, y_train, max_prototypes_per_class=12)

    # Calibrate novelty threshold on validation benign samples (90th percentile)
    val_benign_embs = val_embs[y_val == 0]
    val_malware_embs = val_embs[y_val == 1]
    tau = detector.calibrate_threshold(val_benign_embs, percentile=90.0)

    # Compute novelty distances
    benign_scores = detector.score(val_benign_embs)
    val_mal_scores = detector.score(val_malware_embs)
    chal_scores = detector.score(chal_embs)

    # Novelty AUROC: separating familiar validation benign from challenge evasive malware
    y_novelty_true = np.concatenate([np.zeros(len(benign_scores)), np.ones(len(chal_scores))])
    y_novelty_scores = np.concatenate([benign_scores, chal_scores])
    novelty_auroc = float(roc_auc_score(y_novelty_true, y_novelty_scores))
    novelty_separation = float(np.mean(chal_scores) - np.mean(benign_scores))

    # Threshold evaluation
    benign_novelty_fpr = float(np.mean(benign_scores > tau))
    chal_novelty_detection = float(np.mean(chal_scores > tau))

    return {
        "embedding_dim": embedding_dim,
        "seed": seed,
        "train_time_sec": float(train_time_sec),
        "calibrated_temperature": float(calibrated_temp),
        "parameter_count": int(param_count),
        "estimated_memory_kb": float(memory_kb),
        "inference_latency_ms": float(latency_ms_per_sample),
        "throughput_samples_per_sec": float(throughput_samples_per_sec),
        # Classification
        "macro_f1": macro_f1,
        "binary_f1": binary_f1,
        "accuracy": acc,
        "balanced_accuracy": bal_acc,
        "precision": prec,
        "recall": rec,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "detection_rate_at_1pct_fpr": dr_at_1pct_fpr,
        "fpr_at_95pct_recall": fpr_at_95pct_recall,
        # Calibration
        "brier_score": brier,
        "ece": ece,
        # Novelty Detection
        "novelty_threshold_tau": float(tau),
        "novelty_auroc": novelty_auroc,
        "novelty_separation": novelty_separation,
        "benign_novelty_fpr": benign_novelty_fpr,
        "challenge_novelty_detection": chal_novelty_detection,
        "mean_benign_distance": float(np.mean(benign_scores)),
        "mean_challenge_distance": float(np.mean(chal_scores)),
        "p90_benign_distance": float(np.percentile(benign_scores, 90)),
        "p90_challenge_distance": float(np.percentile(chal_scores, 90)),
    }


# ---------------------------------------------------------------------------
# Continual Learning Benchmark Routine
# ---------------------------------------------------------------------------

def run_continual_learning_for_dimension(
    embedding_dim: int,
    temporal_batches: List[Dict[str, Any]],
    strategies: List[str] = ("none", "random", "uncertainty", "uncertainty_diversity"),
    seed: int = 42,
) -> Dict[str, Any]:
    """Runs continual learning benchmark across chronological T1..T5 batches for a candidate dimension."""
    results: Dict[str, Any] = {}
    for strat in strategies:
        trainer = ContinualTrainer(
            strategy_id=strat,
            buffer_capacity=100,
            label_budget_per_batch=50,
            epochs_per_batch=8,
            learning_rate=0.001,
            batch_size=32,
            embedding_dim=embedding_dim,
            seed=seed,
            device="cpu",
        )
        report = trainer.run_benchmark(temporal_batches)
        results[strat] = {
            "final_macro_f1": float(report.final_macro_f1),
            "final_fpr": float(report.final_fpr),
            "backward_transfer_bwt": float(report.backward_transfer),
            "catastrophic_forgetting": float(report.catastrophic_forgetting),
            "train_time_sec": float(report.training_time_sec),
        }
    return results


# ---------------------------------------------------------------------------
# Multi-Seed Aggregation
# ---------------------------------------------------------------------------

def aggregate_seed_results(dim_runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes mean, std, min, max, and 95% CI for all numeric metrics across seeds."""
    agg: Dict[str, Any] = {"runs_count": len(dim_runs)}
    numeric_keys = [
        k for k, v in dim_runs[0].items()
        if isinstance(v, (int, float)) and k not in ("seed", "embedding_dim")
    ]
    for key in numeric_keys:
        vals = [r[key] for r in dim_runs]
        mean_val = float(np.mean(vals))
        std_val = float(np.std(vals))
        min_val = float(np.min(vals))
        max_val = float(np.max(vals))
        ci95 = float(1.96 * (std_val / np.sqrt(len(vals)))) if len(vals) > 1 else 0.0
        agg[key] = {
            "mean": mean_val,
            "std": std_val,
            "min": min_val,
            "max": max_val,
            "ci95": ci95,
        }
    return agg


# ---------------------------------------------------------------------------
# Plot Generation (Publication-Grade Visualizations)
# ---------------------------------------------------------------------------

def generate_ablation_plots(
    aggregated_results: Dict[str, Any],
    cl_results: Dict[str, Any],
    output_dir: Path,
) -> None:
    """Generates 9 publication-grade ablation study plots."""
    output_dir.mkdir(parents=True, exist_ok=True)
    dims = sorted([int(d) for d in aggregated_results.keys()])
    dim_labels = [str(d) for d in dims]

    # Style configuration
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    color_primary = "#0969da"
    color_secondary = "#2da44e"
    color_accent = "#cf222e"
    color_purple = "#8250df"

    def get_mean_std(key: str) -> Tuple[List[float], List[float]]:
        means = [aggregated_results[str(d)][key]["mean"] for d in dims]
        stds = [aggregated_results[str(d)][key]["std"] for d in dims]
        return means, stds

    # -------------------------------------------------------------
    # Plot 1: Embedding Dimension vs Macro-F1
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    means, stds = get_mean_std("macro_f1")
    ax.errorbar(dims, means, yerr=stds, fmt="o-", color=color_primary, ecolor="#8cc5ff", elinewidth=2, capsize=4, linewidth=2, markersize=7)
    for d, m in zip(dims, means):
        ax.annotate(f"{m:.4f}", (d, m), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9, fontweight="bold")
    ax.set_title("Embedding Dimension vs Classification Macro-F1", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Embedding Dimensionality", fontsize=11)
    ax.set_ylabel("Macro-F1 (Validation Split, Mean ± 1 SD)", fontsize=11)
    ax.set_xticks(dims)
    ax.set_ylim(min(means) - 0.03, max(means) + 0.03)
    fig.tight_layout()
    fig.savefig(output_dir / "plot1_macro_f1.png")
    plt.close(fig)

    # -------------------------------------------------------------
    # Plot 2: Embedding Dimension vs PR-AUC
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    means, stds = get_mean_std("pr_auc")
    ax.errorbar(dims, means, yerr=stds, fmt="s-", color=color_secondary, ecolor="#85e89d", elinewidth=2, capsize=4, linewidth=2, markersize=7)
    for d, m in zip(dims, means):
        ax.annotate(f"{m:.4f}", (d, m), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9)
    ax.set_title("Embedding Dimension vs Precision-Recall AUC (PR-AUC)", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Embedding Dimensionality", fontsize=11)
    ax.set_ylabel("PR-AUC (Validation Split)", fontsize=11)
    ax.set_xticks(dims)
    fig.tight_layout()
    fig.savefig(output_dir / "plot2_pr_auc.png")
    plt.close(fig)

    # -------------------------------------------------------------
    # Plot 3: Embedding Dimension vs Detection Rate @ 1% FPR
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    means, stds = get_mean_std("detection_rate_at_1pct_fpr")
    ax.errorbar(dims, means, yerr=stds, fmt="^-", color=color_purple, ecolor="#d8b9ff", elinewidth=2, capsize=4, linewidth=2, markersize=7)
    for d, m in zip(dims, means):
        ax.annotate(f"{m:.3f}", (d, m), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9)
    ax.set_title("Embedding Dimension vs Detection Rate @ 1% FPR", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Embedding Dimensionality", fontsize=11)
    ax.set_ylabel("True Positive Rate at fixed 1% False Positive Rate", fontsize=11)
    ax.set_xticks(dims)
    fig.tight_layout()
    fig.savefig(output_dir / "plot3_detection_rate_at_1pct_fpr.png")
    plt.close(fig)

    # -------------------------------------------------------------
    # Plot 4: Embedding Dimension vs FPR @ 95% Recall
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    means, stds = get_mean_std("fpr_at_95pct_recall")
    ax.errorbar(dims, means, yerr=stds, fmt="v-", color=color_accent, ecolor="#ffb4a8", elinewidth=2, capsize=4, linewidth=2, markersize=7)
    for d, m in zip(dims, means):
        ax.annotate(f"{m:.3f}", (d, m), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9)
    ax.set_title("Embedding Dimension vs False Positive Rate @ 95% Recall", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Embedding Dimensionality", fontsize=11)
    ax.set_ylabel("FPR (Lower is Better)", fontsize=11)
    ax.set_xticks(dims)
    fig.tight_layout()
    fig.savefig(output_dir / "plot4_fpr_at_95pct_recall.png")
    plt.close(fig)

    # -------------------------------------------------------------
    # Plot 5: Embedding Dimension vs Novelty AUROC & Separation
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(8, 5), dpi=300)
    means_auroc, stds_auroc = get_mean_std("novelty_auroc")
    means_sep, _ = get_mean_std("novelty_separation")

    ax1.errorbar(dims, means_auroc, yerr=stds_auroc, fmt="o-", color=color_primary, label="Novelty AUROC (vs Challenge)", linewidth=2, markersize=7)
    ax1.set_xlabel("Embedding Dimensionality", fontsize=11)
    ax1.set_ylabel("Novelty AUROC", color=color_primary, fontsize=11)
    ax1.tick_params(axis="y", labelcolor=color_primary)
    ax1.set_xticks(dims)

    ax2 = ax1.twinx()
    ax2.plot(dims, means_sep, "s--", color=color_secondary, label="Cosine Separation Distance", linewidth=2, markersize=6)
    ax2.set_ylabel("Cosine Separation Δ (Challenge − Benign)", color=color_secondary, fontsize=11)
    ax2.tick_params(axis="y", labelcolor=color_secondary)
    ax2.grid(False)

    ax1.set_title("Embedding Dimension vs Out-of-Distribution Novelty Quality", fontsize=13, fontweight="bold", pad=12)
    fig.tight_layout()
    fig.savefig(output_dir / "plot5_novelty_auroc.png")
    plt.close(fig)

    # -------------------------------------------------------------
    # Plot 6: Embedding Dimension vs Catastrophic Forgetting
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    for strat, col, style in [
        ("none", "#cf222e", "o:"),
        ("random", "#d29922", "s--"),
        ("uncertainty", "#0969da", "^-."),
        ("uncertainty_diversity", "#2da44e", "D-"),
    ]:
        strat_forgetting = []
        for d in dims:
            dim_str = str(d)
            if dim_str in cl_results and strat in cl_results[dim_str]:
                strat_forgetting.append(cl_results[dim_str][strat]["catastrophic_forgetting"])
            else:
                strat_forgetting.append(0.0)
        ax.plot(dims, strat_forgetting, style, color=col, label=strat.replace("_", " ").title(), linewidth=2, markersize=6)

    ax.set_title("Embedding Dimension vs Catastrophic Forgetting across Replay Strategies", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Embedding Dimensionality", fontsize=11)
    ax.set_ylabel("Catastrophic Forgetting FT (Lower is Better)", fontsize=11)
    ax.set_xticks(dims)
    ax.legend(frameon=True, fontsize=10)
    fig.tight_layout()
    fig.savefig(output_dir / "plot6_catastrophic_forgetting.png")
    plt.close(fig)

    # -------------------------------------------------------------
    # Plot 7: Embedding Dimension vs Inference Latency & Throughput
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(8, 5), dpi=300)
    lat_means, _ = get_mean_std("inference_latency_ms")
    tp_means, _ = get_mean_std("throughput_samples_per_sec")

    ax1.plot(dims, lat_means, "o-", color=color_accent, linewidth=2, markersize=7)
    ax1.set_xlabel("Embedding Dimensionality", fontsize=11)
    ax1.set_ylabel("Inference Latency (ms / sample)", color=color_accent, fontsize=11)
    ax1.tick_params(axis="y", labelcolor=color_accent)
    ax1.set_xticks(dims)

    ax2 = ax1.twinx()
    ax2.plot(dims, tp_means, "s--", color="#1f883d", linewidth=2, markersize=6)
    ax2.set_ylabel("Throughput (samples / sec)", color="#1f883d", fontsize=11)
    ax2.tick_params(axis="y", labelcolor="#1f883d")
    ax2.grid(False)

    ax1.set_title("Embedding Dimension vs Computational Inference Latency & Throughput", fontsize=13, fontweight="bold", pad=12)
    fig.tight_layout()
    fig.savefig(output_dir / "plot7_inference_latency.png")
    plt.close(fig)

    # -------------------------------------------------------------
    # Plot 8: Embedding Dimension vs Memory & Checkpoint Size
    # -------------------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(8, 5), dpi=300)
    mem_means, _ = get_mean_std("estimated_memory_kb")
    param_means, _ = get_mean_std("parameter_count")

    ax1.bar([d - 4 for d in dims], mem_means, width=8, color="#54aeff", label="Memory (KB)", alpha=0.85)
    ax1.set_xlabel("Embedding Dimensionality", fontsize=11)
    ax1.set_ylabel("Weights Memory Footprint (KB)", color="#0969da", fontsize=11)
    ax1.tick_params(axis="y", labelcolor="#0969da")
    ax1.set_xticks(dims)

    ax2 = ax1.twinx()
    ax2.plot(dims, param_means, "D-", color="#8250df", label="Parameter Count", linewidth=2.5, markersize=7)
    ax2.set_ylabel("Total Neural Parameters", color="#8250df", fontsize=11)
    ax2.tick_params(axis="y", labelcolor="#8250df")
    ax2.grid(False)

    ax1.set_title("Embedding Dimension vs Model Capacity and Memory Footprint", fontsize=13, fontweight="bold", pad=12)
    fig.tight_layout()
    fig.savefig(output_dir / "plot8_memory_checkpoint_size.png")
    plt.close(fig)

    # -------------------------------------------------------------
    # Plot 9: Performance vs Computational Cost (Pareto Efficiency)
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    macro_means, _ = get_mean_std("macro_f1")
    novelty_means, _ = get_mean_std("novelty_auroc")
    combined_perf = [0.6 * m + 0.4 * n for m, n in zip(macro_means, novelty_means)]
    costs = [lat * (mem / 100.0) for lat, mem in zip(lat_means, mem_means)]

    scatter = ax.scatter(costs, combined_perf, s=[d * 1.5 for d in dims], c=dims, cmap="viridis", alpha=0.9, edgecolors="black", linewidth=1.5)
    cbar = plt.colorbar(scatter, ax=ax)
    cbar.set_label("Embedding Dimension (D)", fontsize=10)

    for d, c, p in zip(dims, costs, combined_perf):
        ax.annotate(f"{d}D", (c, p), textcoords="offset points", xytext=(8, 5), fontsize=10, fontweight="bold")

    ax.set_title("Pareto Efficiency: Overall Utility vs Computational Cost", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Normalized Computational Cost (Latency × Memory Index)", fontsize=11)
    ax.set_ylabel("Combined Utility (0.6 × Macro-F1 + 0.4 × Novelty AUROC)", fontsize=11)
    fig.tight_layout()
    fig.savefig(output_dir / "plot9_pareto_performance_vs_cost.png")
    plt.close(fig)
    print(f"[+] Successfully generated 9 publication-grade ablation plots in {output_dir}")


# ---------------------------------------------------------------------------
# Main Ablation Runner
# ---------------------------------------------------------------------------

def run_embedding_ablation_study(
    data_dir: Path,
    output_dir: Path,
    checkpoints_dir: Path,
    dims: List[int],
    seeds: List[int],
    quick_mode: bool = False,
) -> Dict[str, Any]:
    """Coordinates full ablation experiment across dimensions, seeds, and replay strategies."""
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoints_dir.mkdir(parents=True, exist_ok=True)

    partial_file = output_dir / "embedding_dimension_partial.json"
    results_json = output_dir / "embedding_dimension_results.json"
    results_csv = output_dir / "embedding_dimension_results.csv"

    # Resumption state check
    raw_runs: Dict[str, List[Dict[str, Any]]] = {str(d): [] for d in dims}
    cl_results: Dict[str, Any] = {}
    if partial_file.is_file():
        try:
            with open(partial_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
                raw_runs.update(saved.get("raw_runs", {}))
                cl_results.update(saved.get("cl_results", {}))
                print(f"[*] Resumed prior progress from {partial_file.name}")
        except Exception as e:
            print(f"[!] Warning reading partial file: {e}")

    # 1. Load EMBER2024 dataset
    print("\n" + "=" * 70)
    print("THREATWEAVER EMBEDDING DIMENSION ABLATION STUDY")
    print(f"Candidate Dimensions: {dims}")
    print(f"Random Seeds: {seeds}")
    print(f"Execution Mode: {'QUICK' if quick_mode else 'FULL SCIENTIFIC'}")
    print("=" * 70)

    win64_q = 1200 if quick_mode else 3000
    dotnet_q = 800 if quick_mode else 2000
    chal_q = 300 if quick_mode else 500

    print("\n[*] Loading and harmonizing real EMBER2024 partitions...")
    X, y, timestamps, X_challenge, y_challenge = load_ablation_dataset(
        data_dir=data_dir,
        win64_quota=win64_q,
        dotnet_quota=dotnet_q,
        challenge_quota=chal_q,
    )

    # 2. Strict Chronological Temporal Split
    print("\n[*] Executing strict chronological temporal split (70% Train, 15% Val, 15% Untouched Test)...")
    splitter = TemporalSplitter(train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)
    split = splitter.split_by_timestamps(timestamps)

    X_train_raw = X[split.train_indices]
    y_train = y[split.train_indices]
    ts_train = timestamps[split.train_indices]

    X_val_raw = X[split.val_indices]
    y_val = y[split.val_indices]
    ts_val = timestamps[split.val_indices]

    X_test_raw = X[split.test_indices]
    y_test = y[split.test_indices]
    ts_test = timestamps[split.test_indices]

    print(f"  [+] Train partition: {len(y_train)} samples (min_ts={ts_train.min()}, max_ts={ts_train.max()})")
    print(f"  [+] Validation partition (for selection): {len(y_val)} samples (min_ts={ts_val.min()}, max_ts={ts_val.max()})")
    print(f"  [+] Untouched Test partition (locked): {len(y_test)} samples (min_ts={ts_test.min()}, max_ts={ts_test.max()})")

    # Fit feature scaler strictly on training split
    scaler = FeatureScaler()
    scaler.fit(X_train_raw)
    X_train = scaler.transform(X_train_raw)
    X_val = scaler.transform(X_val_raw)
    X_test = scaler.transform(X_test_raw)
    X_chal_scaled = scaler.transform(X_challenge)

    # 3. Dimension Ablation Iteration
    epochs = 12 if quick_mode else 20
    for dim in dims:
        dim_str = str(dim)
        print(f"\n>>> Running Ablation for Embedding Dimension: {dim}-D <<<")
        existing_seeds = [r["seed"] for r in raw_runs.get(dim_str, [])]

        best_model_for_dim: Optional[ThreatClassifier] = None
        best_val_f1 = -1.0

        for seed in seeds:
            if seed in existing_seeds:
                print(f"  [-] Dimension {dim}-D seed {seed} already computed. Skipping.")
                continue

            print(f"  [*] Training {dim}-D model (seed={seed}, epochs={epochs})...")
            model, t_train, cal_temp = train_ablation_model(
                embedding_dim=dim,
                X_train=X_train,
                y_train=y_train,
                X_val=X_val,
                y_val=y_val,
                seed=seed,
                epochs=epochs,
                batch_size=64,
                lr=1e-3,
            )

            metrics = evaluate_ablation_run(
                model=model,
                scaler=scaler,
                X_val=X_val,
                y_val=y_val,
                X_train=X_train,
                y_train=y_train,
                X_challenge=X_chal_scaled,
                y_challenge=y_challenge,
                embedding_dim=dim,
                seed=seed,
                train_time_sec=t_train,
                calibrated_temp=cal_temp,
            )
            raw_runs[dim_str].append(metrics)

            if metrics["macro_f1"] > best_val_f1:
                best_val_f1 = metrics["macro_f1"]
                best_model_for_dim = model

            print(f"      Macro-F1: {metrics['macro_f1']:.4f} | PR-AUC: {metrics['pr_auc']:.4f} | DR@1%FPR: {metrics['detection_rate_at_1pct_fpr']:.4f} | Novelty AUROC: {metrics['novelty_auroc']:.4f} | Latency: {metrics['inference_latency_ms']:.3f}ms")

        # Save representative checkpoint for this dimension
        if best_model_for_dim is None and len(raw_runs[dim_str]) > 0:
            # Retrain best seed if resumed without in-memory model
            best_seed = max(raw_runs[dim_str], key=lambda x: x["macro_f1"])["seed"]
            best_model_for_dim, _, _ = train_ablation_model(
                embedding_dim=dim,
                X_train=X_train,
                y_train=y_train,
                X_val=X_val,
                y_val=y_val,
                seed=best_seed,
                epochs=epochs,
            )

        if best_model_for_dim is not None:
            ckpt_path = checkpoints_dir / f"threatweaver_{dim}d.pt"
            # Extract prototypes for checkpoint
            train_embs = best_model_for_dim(torch.tensor(X_train, dtype=torch.float32)).embeddings.detach().numpy()
            det = NoveltyDetector()
            det.fit_prototypes(train_embs, y_train, max_prototypes_per_class=10)
            protos = [
                {"label": p.label, "family_name": p.family_name, "centroid": p.centroid.tolist(), "sample_count": p.sample_count}
                for p in det.prototypes
            ]
            save_checkpoint(
                model=best_model_for_dim,
                save_path=ckpt_path,
                feature_mean=scaler.mean.tolist() if scaler.mean is not None else None,
                feature_std=scaler.std.tolist() if scaler.std is not None else None,
                novelty_threshold=float(det.calibrate_threshold(train_embs[y_train == 0])),
                prototypes=protos,
                metadata={
                    "ablation_embedding_dim": dim,
                    "best_val_macro_f1": best_val_f1,
                    "epochs": epochs,
                    "schema_version": "1.0",
                },
                sign=True,
            )
            print(f"  [+] Checkpoint saved: {ckpt_path.name} (HMAC signed)")

        # Continual learning evaluation for candidate dimension
        if dim_str not in cl_results:
            print(f"  [*] Benchmarking continual learning adaptation across T1..T5 for {dim}-D...")
            # Build 5 temporal batches from training samples chronologically
            t_batches_indices = splitter.partition_temporal_batches(ts_train, num_batches=5)
            temporal_batches = []
            for b_idx, idx_set in enumerate(t_batches_indices):
                temporal_batches.append({
                    "batch_id": b_idx,
                    "period": f"T{b_idx + 1}",
                    "features": X_train_raw[idx_set],
                    "labels": y_train[idx_set],
                    "timestamps": ts_train[idx_set],
                    "families": ["PE-Binary"] * len(idx_set),
                })
            strats = ["none", "random", "uncertainty"] if quick_mode else ["none", "random", "uncertainty", "uncertainty_diversity"]
            cl_results[dim_str] = run_continual_learning_for_dimension(
                embedding_dim=dim,
                temporal_batches=temporal_batches,
                strategies=strats,
                seed=42,
            )

        # Save intermediate state
        with open(partial_file, "w", encoding="utf-8") as f:
            json.dump({"raw_runs": raw_runs, "cl_results": cl_results}, f, indent=2)

    # 4. Aggregation & Summary Generation
    print("\n" + "=" * 70)
    print("COMPUTING MULTI-SEED AGGREGATES & SUMMARY METRICS")
    print("=" * 70)

    aggregated_results: Dict[str, Any] = {}
    summary_table_rows: List[Dict[str, Any]] = []

    for dim in dims:
        dim_str = str(dim)
        runs = raw_runs[dim_str]
        agg = aggregate_seed_results(runs)
        aggregated_results[dim_str] = agg

        row = {
            "Dimension": dim,
            "Macro-F1": f"{agg['macro_f1']['mean']:.4f} ± {agg['macro_f1']['std']:.4f}",
            "ROC-AUC": f"{agg['roc_auc']['mean']:.4f} ± {agg['roc_auc']['std']:.4f}",
            "PR-AUC": f"{agg['pr_auc']['mean']:.4f} ± {agg['pr_auc']['std']:.4f}",
            "Detection @1% FPR": f"{agg['detection_rate_at_1pct_fpr']['mean']:.4f} ± {agg['detection_rate_at_1pct_fpr']['std']:.4f}",
            "FPR @95% Recall": f"{agg['fpr_at_95pct_recall']['mean']:.4f} ± {agg['fpr_at_95pct_recall']['std']:.4f}",
            "Brier Score": f"{agg['brier_score']['mean']:.4f} ± {agg['brier_score']['std']:.4f}",
            "ECE": f"{agg['ece']['mean']:.4f} ± {agg['ece']['std']:.4f}",
            "Novelty AUROC": f"{agg['novelty_auroc']['mean']:.4f} ± {agg['novelty_auroc']['std']:.4f}",
            "BWT (CL)": f"{cl_results.get(dim_str, {}).get('uncertainty_diversity', cl_results.get(dim_str, {}).get('uncertainty', {})).get('backward_transfer_bwt', 0.0):.4f}",
            "Forgetting (CL)": f"{cl_results.get(dim_str, {}).get('uncertainty_diversity', cl_results.get(dim_str, {}).get('uncertainty', {})).get('catastrophic_forgetting', 0.0):.4f}",
            "Latency (ms)": f"{agg['inference_latency_ms']['mean']:.3f} ms",
            "Memory (KB)": f"{agg['estimated_memory_kb']['mean']:.1f} KB",
        }
        summary_table_rows.append(row)

    # Print summary table to console
    print(f"\n{'Dim':>5} | {'Macro-F1':>17} | {'ROC-AUC':>17} | {'PR-AUC':>17} | {'Novelty AUROC':>17} | {'Latency':>10}")
    print("-" * 92)
    for r in summary_table_rows:
        print(f"{r['Dimension']:>5} | {r['Macro-F1']:>17} | {r['ROC-AUC']:>17} | {r['PR-AUC']:>17} | {r['Novelty AUROC']:>17} | {r['Latency (ms)']:>10}")

    # Export results to JSON
    export_payload = {
        "metadata": {
            "title": "ThreatWeaver Embedding Dimension Ablation Study",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "dimensions_evaluated": dims,
            "seeds_evaluated": seeds,
            "samples_train": len(y_train),
            "samples_val": len(y_val),
            "samples_test": len(y_test),
            "samples_challenge": len(y_challenge),
            "quick_mode": quick_mode,
        },
        "aggregated_results": aggregated_results,
        "cl_results": cl_results,
        "raw_runs": raw_runs,
        "summary_table": summary_table_rows,
        "test_partition": {
            "num_samples": len(y_test),
            "timestamps_range": [int(ts_test.min()), int(ts_test.max())],
        },
    }
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(export_payload, f, indent=2)
    print(f"\n[+] Exported structured JSON results to: {results_json}")

    # Export results to CSV
    fieldnames = list(summary_table_rows[0].keys())
    with open(results_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_table_rows)
    print(f"[+] Exported summary CSV results to: {results_csv}")

    # 5. Generate Visualizations
    plots_dir = output_dir / "embedding_dimension"
    generate_ablation_plots(
        aggregated_results=aggregated_results,
        cl_results=cl_results,
        output_dir=plots_dir,
    )

    return export_payload


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatWeaver Embedding Dimension Ablation Study Engine")
    parser.add_argument("--data-dir", default="data/ember2024", help="Path to EMBER2024 dataset root")
    parser.add_argument("--output-dir", default="artifacts/benchmarks", help="Output directory for reports and plots")
    parser.add_argument("--checkpoints-dir", default="artifacts/checkpoints", help="Directory for checkpoint storage")
    parser.add_argument("--dims", nargs="+", type=int, default=[32, 64, 96, 128, 192, 256], help="Embedding dimensions to test")
    parser.add_argument("--seeds", nargs="+", type=int, default=[42, 1337, 2026], help="Random seeds for multi-seed evaluation")
    parser.add_argument("--quick", action="store_true", help="Run rapid ablation study with reduced sample quotas")
    parser.add_argument("--full", action="store_true", help="Run comprehensive multi-seed ablation study on full quota")

    args = parser.parse_args()
    dims = [32, 64, 128] if args.quick and not args.dims else args.dims
    seeds = [42] if args.quick and not args.seeds else args.seeds

    run_embedding_ablation_study(
        data_dir=Path(args.data_dir),
        output_dir=Path(args.output_dir),
        checkpoints_dir=Path(args.checkpoints_dir),
        dims=dims,
        seeds=seeds,
        quick_mode=args.quick and not args.full,
    )


if __name__ == "__main__":
    main()
