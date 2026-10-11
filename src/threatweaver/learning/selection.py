"""Replay selection strategies for continual learning in ThreatWeaver."""

from __future__ import annotations

import abc
from typing import List, Optional

import numpy as np
from sklearn.cluster import MiniBatchKMeans

from threatweaver.learning.replay_buffer import ReplaySample


class ReplaySelector(abc.ABC):
    """Abstract interface for continual learning sample selection."""

    def __init__(self, budget: int = 50, seed: int = 42):
        self.budget = budget
        self.rng = np.random.default_rng(seed)

    @abc.abstractmethod
    def select(self, candidates: List[ReplaySample]) -> List[ReplaySample]:
        """Selects up to `budget` samples from candidates for replay buffering."""
        pass


class NoReplaySelector(ReplaySelector):
    """Strategy A: No replay (naive fine-tuning baseline)."""

    def select(self, candidates: List[ReplaySample]) -> List[ReplaySample]:
        return []


class RandomReplaySelector(ReplaySelector):
    """Strategy B: Uniform random replay selection."""

    def select(self, candidates: List[ReplaySample]) -> List[ReplaySample]:
        if not candidates or self.budget <= 0:
            return []
        sample_count = min(self.budget, len(candidates))
        chosen_indices = self.rng.choice(len(candidates), size=sample_count, replace=False)
        return [candidates[i] for i in chosen_indices]


class UncertaintyReplaySelector(ReplaySelector):
    """Strategy C: Uncertainty-guided replay.
    
    Selects samples with highest predictive entropy / decision boundary ambiguity.
    """

    def select(self, candidates: List[ReplaySample]) -> List[ReplaySample]:
        if not candidates or self.budget <= 0:
            return []
        
        # Sort candidates descending by predictive uncertainty
        sorted_candidates = sorted(candidates, key=lambda s: s.uncertainty, reverse=True)
        return sorted_candidates[: self.budget]


class UncertaintyDiversityReplaySelector(ReplaySelector):
    """Strategy D: Uncertainty + Diversity-guided replay.
    
    Clusters candidates in embedding space and selects the most uncertain sample
    from each cluster, balancing manifold coverage with decision boundary focus.
    """

    def select(self, candidates: List[ReplaySample]) -> List[ReplaySample]:
        if not candidates or self.budget <= 0:
            return []
        
        if len(candidates) <= self.budget:
            return list(candidates)

        # Extract embeddings
        embeddings = [
            s.embedding if s.embedding is not None else s.features[:32]
            for s in candidates
        ]
        X = np.stack(embeddings, axis=0)

        k = min(self.budget, len(candidates))
        try:
            kmeans = MiniBatchKMeans(n_clusters=k, random_state=42, n_init="auto")
            labels = kmeans.fit_predict(X)
        except Exception:
            # Fallback to random if clustering fails
            return RandomReplaySelector(self.budget).select(candidates)

        selected: List[ReplaySample] = []
        selected_ids = set()
        for cluster_id in range(k):
            cluster_members = [
                candidates[idx]
                for idx, lbl in enumerate(labels)
                if lbl == cluster_id
            ]
            if cluster_members:
                most_uncertain = max(cluster_members, key=lambda s: s.uncertainty)
                if most_uncertain.sample_id not in selected_ids:
                    selected.append(most_uncertain)
                    selected_ids.add(most_uncertain.sample_id)

        # If any slots remain due to empty clusters, fill with next most uncertain candidates
        if len(selected) < self.budget:
            remaining = [c for c in candidates if c.sample_id not in selected_ids]
            remaining.sort(key=lambda s: s.uncertainty, reverse=True)
            for r in remaining:
                if len(selected) >= self.budget:
                    break
                selected.append(r)
                selected_ids.add(r.sample_id)

        return selected



def get_replay_selector(strategy_name: str, budget: int = 50, seed: int = 42) -> ReplaySelector:
    """Factory helper to instantiate a selection strategy."""
    strat = strategy_name.lower().strip()
    if strat in ("none", "no_replay", "naive"):
        return NoReplaySelector(budget=budget, seed=seed)
    elif strat in ("random", "uniform"):
        return RandomReplaySelector(budget=budget, seed=seed)
    elif strat in ("uncertainty", "entropy"):
        return UncertaintyReplaySelector(budget=budget, seed=seed)
    elif strat in ("uncertainty_diversity", "uncertainty_plus_diversity", "diverse"):
        return UncertaintyDiversityReplaySelector(budget=budget, seed=seed)
    else:
        raise ValueError(f"Unknown replay selection strategy: {strategy_name}")
