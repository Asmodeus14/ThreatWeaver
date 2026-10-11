"""Continual learning training loop and experiment executor for ThreatWeaver."""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from threatweaver.data.loader import ThreatDataset, create_dataloader
from threatweaver.data.preprocessing import FeatureScaler
from threatweaver.evaluation.forgetting import (
    ContinualEvaluationReport,
    compute_catastrophic_forgetting,
)
from threatweaver.evaluation.metrics import compute_classification_metrics
from threatweaver.learning.replay_buffer import ReplayBuffer, ReplaySample
from threatweaver.learning.selection import get_replay_selector
from threatweaver.models.classifier import ThreatClassifier, save_checkpoint
from threatweaver.models.novelty import NoveltyDetector


def compute_predictive_entropy(probabilities: np.ndarray) -> np.ndarray:
    """Computes Shannon entropy of predicted probability distribution."""
    # probabilities: (N, C)
    eps = 1e-12
    p = np.clip(probabilities, eps, 1.0)
    entropy = -np.sum(p * np.log2(p), axis=-1)
    return entropy


class ContinualTrainer:
    """Manages sequential training across temporal batches and benchmarks replay strategies."""

    def __init__(
        self,
        strategy_id: str = "random",
        buffer_capacity: int = 100,
        label_budget_per_batch: int = 50,
        epochs_per_batch: int = 8,
        learning_rate: float = 0.001,
        weight_decay: float = 1e-4,
        batch_size: int = 32,
        seed: int = 42,
        device: str = "cpu",
    ):
        self.strategy_id = strategy_id
        self.buffer_capacity = buffer_capacity
        self.label_budget = label_budget_per_batch
        self.epochs = epochs_per_batch
        self.lr = learning_rate
        self.weight_decay = weight_decay
        self.batch_size = batch_size
        self.seed = seed
        self.device = torch.device(device if (device != "auto" and torch.cuda.is_available()) else "cpu")

        # Set random seeds for reproducibility
        torch.manual_seed(seed)
        np.random.seed(seed)

        self.replay_buffer = ReplayBuffer(capacity=buffer_capacity, seed=seed)
        self.selector = get_replay_selector(strategy_id, budget=label_budget_per_batch, seed=seed)
        self.model = ThreatClassifier(input_dim=256, num_classes=2).to(self.device)
        self.scaler = FeatureScaler()
        self.novelty_detector = NoveltyDetector()

    def train_single_batch(
        self,
        train_features: np.ndarray,
        train_labels: np.ndarray,
    ) -> float:
        """Trains model on features combined with replay buffer."""
        # Include replay buffer if available
        if len(self.replay_buffer) > 0 and self.strategy_id != "none":
            rep_X, rep_y = self.replay_buffer.to_arrays()
            combined_X = np.vstack([train_features, rep_X])
            combined_y = np.concatenate([train_labels, rep_y])
        else:
            combined_X = train_features
            combined_y = train_labels

        ds = ThreatDataset(features=combined_X, labels=combined_y)
        loader = create_dataloader(ds, batch_size=self.batch_size, shuffle=True)

        criterion = nn.CrossEntropyLoss()
        optimizer = optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=self.weight_decay)

        self.model.train()
        total_loss = 0.0
        for _ in range(self.epochs):
            for batch in loader:
                x = batch["features"].to(self.device)
                y = batch["label"].to(self.device)

                optimizer.zero_grad()
                out = self.model(x)
                loss = criterion(out.logits, y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

        return total_loss

    def evaluate_on_features(
        self, features: np.ndarray, labels: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Runs evaluation pass, returning (predictions, probabilities, embeddings)."""
        self.model.eval()
        ds = ThreatDataset(features=features, labels=labels)
        loader = create_dataloader(ds, batch_size=self.batch_size, shuffle=False)

        all_preds = []
        all_probs = []
        all_embs = []

        with torch.no_grad():
            for batch in loader:
                x = batch["features"].to(self.device)
                out = self.model(x)
                probs = out.probabilities.cpu().numpy()
                preds = np.argmax(probs, axis=-1)
                embs = out.embeddings.cpu().numpy()

                all_preds.append(preds)
                all_probs.append(probs)
                all_embs.append(embs)

        preds_arr = np.concatenate(all_preds, axis=0) if all_preds else np.empty((0,), dtype=np.int64)
        probs_arr = np.concatenate(all_probs, axis=0) if all_probs else np.empty((0, 2), dtype=np.float32)
        embs_arr = np.concatenate(all_embs, axis=0) if all_embs else np.empty((0, 32), dtype=np.float32)

        return preds_arr, probs_arr, embs_arr

    def run_benchmark(
        self,
        batch_datasets: List[Dict[str, Any]],
    ) -> ContinualEvaluationReport:
        """Executes chronological continual learning benchmark across sequential batches."""
        start_time = time.time()
        T = len(batch_datasets)
        r_matrix = np.zeros((T, T), dtype=np.float32)

        # Scale features using batch 0 as reference distribution
        self.scaler.fit(batch_datasets[0]["features"])

        for t in range(T):
            cur_batch = batch_datasets[t]
            raw_X = cur_batch["features"]
            y = cur_batch["labels"]
            scaled_X = self.scaler.transform(raw_X)
            families = cur_batch.get("families", ["Unknown"] * len(y))

            # Train on current batch + replay buffer
            self.train_single_batch(scaled_X, y)

            # Evaluate uncertainty and embeddings on current batch for replay selection
            preds, probs, embs = self.evaluate_on_features(scaled_X, y)
            uncertainties = compute_predictive_entropy(probs)

            # Build candidates for replay buffer
            candidates: List[ReplaySample] = []
            for i in range(len(scaled_X)):
                candidates.append(
                    ReplaySample(
                        features=scaled_X[i],
                        label=int(y[i]),
                        sample_id=f"b{t}_s{i}",
                        family=families[i],
                        timestamp=int(cur_batch.get("timestamps", np.zeros(len(y)))[i]),
                        uncertainty=float(uncertainties[i]),
                        embedding=embs[i],
                    )
                )

            # Select samples using current strategy and add to replay buffer
            if self.strategy_id != "none":
                chosen = self.selector.select(candidates)
                self.replay_buffer.extend(chosen)

            # Evaluate model on all seen batches (0 .. t) to populate row t of R matrix
            for past_j in range(t + 1):
                past_batch = batch_datasets[past_j]
                past_scaled_X = self.scaler.transform(past_batch["features"])
                past_y = past_batch["labels"]
                past_preds, _, _ = self.evaluate_on_features(past_scaled_X, past_y)
                metrics = compute_classification_metrics(past_y, past_preds)
                r_matrix[t, past_j] = metrics.macro_f1

        # Fit prototypes and threshold on final validation data
        all_rep_X, all_rep_y = self.replay_buffer.to_arrays()
        if len(all_rep_X) > 0:
            _, _, final_embs = self.evaluate_on_features(all_rep_X, all_rep_y)
            self.novelty_detector.fit_prototypes(final_embs, all_rep_y)
            self.novelty_detector.calibrate_threshold(final_embs, percentile=95.0)

        total_time = time.time() - start_time
        forgetting, bwt = compute_catastrophic_forgetting(r_matrix)

        # Evaluate final FPR across all batches
        all_X_list = [self.scaler.transform(b["features"]) for b in batch_datasets]
        all_y_list = [b["labels"] for b in batch_datasets]
        full_X = np.vstack(all_X_list)
        full_y = np.concatenate(all_y_list)
        full_preds, _, _ = self.evaluate_on_features(full_X, full_y)
        final_metrics = compute_classification_metrics(full_y, full_preds)

        return ContinualEvaluationReport(
            strategy_id=self.strategy_id,
            strategy_name=f"Strategy: {self.strategy_id}",
            num_batches=T,
            r_matrix=r_matrix,
            catastrophic_forgetting=forgetting,
            backward_transfer=bwt,
            final_macro_f1=final_metrics.macro_f1,
            final_fpr=final_metrics.false_positive_rate,
            training_time_sec=total_time,
            peak_ram_mb=0.0,
            model_size_kb=float(sum(p.numel() * p.element_size() for p in self.model.parameters()) / 1024.0),
        )
