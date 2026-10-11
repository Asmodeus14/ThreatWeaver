"""Novelty detection and similarity exploration based on learned embeddings.

Uses calibrated distance thresholds in normalized embedding space to distinguish
between familiar samples and out-of-distribution / unfamiliar files without conflating
novelty with maliciousness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch


@dataclass
class PrototypeCluster:
    """Cluster prototype in embedding space."""
    label: int                   # 0 = Benign, 1 = Malware
    family_name: str             # e.g., "Benign-System", "Ransomware-Variant", etc.
    centroid: np.ndarray         # Shape: (embedding_dim,), L2-normalized
    sample_count: int = 1


@dataclass
class NoveltyAssessment:
    """Structured result of novelty evaluation."""
    is_novel: bool
    novelty_score: float         # Cosine distance to nearest known prototype (0.0 to 2.0)
    calibrated_threshold: float
    nearest_family: str
    nearest_similarity: float    # Cosine similarity (1.0 - distance, [-1.0, 1.0])
    status_label: str            # "Familiar" or "Unfamiliar"
    explanation: str


class NoveltyDetector:
    """Embedding-space novelty detector using calibrated cosine distances."""

    def __init__(
        self,
        distance_metric: str = "cosine",
        calibrated_threshold: float = 0.40,
    ):
        self.distance_metric = distance_metric
        self.threshold = calibrated_threshold
        self.prototypes: List[PrototypeCluster] = []

    def compute_distance(self, a: np.ndarray, b: np.ndarray) -> float:
        """Computes distance between two L2-normalized vectors."""
        if self.distance_metric == "cosine":
            # For unit vectors, cosine distance is 1.0 - dot_product
            sim = float(np.dot(a, b))
            return max(0.0, 1.0 - sim)
        else:
            return float(np.linalg.norm(a - b))

    def fit_prototypes(
        self,
        embeddings: np.ndarray,
        labels: np.ndarray,
        family_names: Optional[List[str]] = None,
        max_prototypes_per_class: int = 10,
    ) -> None:
        """Extracts cluster centroids for known classes/families from training data."""
        self.prototypes = []
        unique_labels = np.unique(labels)

        for lbl in unique_labels:
            mask = (labels == lbl)
            class_embs = embeddings[mask]
            if len(class_embs) == 0:
                continue

            default_family = "Malware" if lbl == 1 else "Benign"

            # Use k-means or representative quantiles if large, otherwise mean centroid
            if len(class_embs) <= max_prototypes_per_class:
                for idx, emb in enumerate(class_embs):
                    name = family_names[idx] if family_names else f"{default_family}-Cluster-{idx+1}"
                    norm_emb = emb / max(np.linalg.norm(emb), 1e-8)
                    self.prototypes.append(
                        PrototypeCluster(
                            label=int(lbl),
                            family_name=name,
                            centroid=norm_emb,
                            sample_count=1,
                        )
                    )
            else:
                # Divide into subclusters via k-means clustering in scikit-learn
                from sklearn.cluster import MiniBatchKMeans
                n_clusters = min(max_prototypes_per_class, len(class_embs))
                kmeans = MiniBatchKMeans(n_clusters=n_clusters, random_state=42, n_init="auto")
                kmeans.fit(class_embs)
                for c_idx, center in enumerate(kmeans.cluster_centers_):
                    norm_center = center / max(np.linalg.norm(center), 1e-8)
                    cluster_size = int(np.sum(kmeans.labels_ == c_idx))
                    self.prototypes.append(
                        PrototypeCluster(
                            label=int(lbl),
                            family_name=f"{default_family}-Cluster-{c_idx+1}",
                            centroid=norm_center,
                            sample_count=cluster_size,
                        )
                    )

    def calibrate_threshold(
        self,
        val_embeddings: np.ndarray,
        percentile: float = 95.0,
    ) -> float:
        """Calibrates novelty threshold on held-out validation set (no test leakage)."""
        if not self.prototypes:
            raise ValueError("Cannot calibrate threshold before fitting prototypes.")

        distances: List[float] = []
        for emb in val_embeddings:
            norm_emb = emb / max(np.linalg.norm(emb), 1e-8)
            min_dist = min(self.compute_distance(norm_emb, p.centroid) for p in self.prototypes)
            distances.append(min_dist)

        self.threshold = float(np.percentile(distances, percentile))
        return self.threshold

    def evaluate_novelty(self, query_embedding: np.ndarray) -> NoveltyAssessment:
        """Evaluates whether an individual sample is unfamiliar or matches known distributions."""
        if not self.prototypes:
            return NoveltyAssessment(
                is_novel=True,
                novelty_score=1.0,
                calibrated_threshold=self.threshold,
                nearest_family="Unknown",
                nearest_similarity=0.0,
                status_label="Uncalibrated",
                explanation="No reference prototypes available in detector.",
            )

        norm_query = query_embedding / max(np.linalg.norm(query_embedding), 1e-8)

        best_dist = float("inf")
        best_proto: Optional[PrototypeCluster] = None

        for proto in self.prototypes:
            dist = self.compute_distance(norm_query, proto.centroid)
            if dist < best_dist:
                best_dist = dist
                best_proto = proto

        is_novel = best_dist > self.threshold
        sim = max(-1.0, min(1.0, 1.0 - best_dist))
        family = best_proto.family_name if best_proto else "Unknown"

        if is_novel:
            status = "Unfamiliar"
            expl = (
                f"Embedding distance ({best_dist:.3f}) exceeds threshold ({self.threshold:.3f}). "
                f"Sample lies outside validated training clusters. Closest cluster: {family} ({sim:.2f} similarity)."
            )
        else:
            status = "Familiar"
            expl = (
                f"Sample aligns with known cluster '{family}' "
                f"(cosine similarity: {sim:.2f}, distance: {best_dist:.3f} <= threshold {self.threshold:.3f})."
            )

        return NoveltyAssessment(
            is_novel=is_novel,
            novelty_score=best_dist,
            calibrated_threshold=self.threshold,
            nearest_family=family,
            nearest_similarity=sim,
            status_label=status,
            explanation=expl,
        )

    def find_nearest_neighbors(
        self, query_embedding: np.ndarray, top_k: int = 3
    ) -> List[Tuple[str, float]]:
        """Returns top-K nearest prototypes with similarity scores.
        
        CAVEAT: Similarity estimates do not establish verified ancestry or malware attribution.
        """
        if not self.prototypes:
            return []

        norm_query = query_embedding / max(np.linalg.norm(query_embedding), 1e-8)
        scored = []
        for p in self.prototypes:
            dist = self.compute_distance(norm_query, p.centroid)
            sim = 1.0 - dist
            scored.append((p.family_name, float(sim)))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]
