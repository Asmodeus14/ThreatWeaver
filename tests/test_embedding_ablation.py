"""Tests for ThreatWeaver embedding dimension ablation study, Pareto analysis, and selector."""

import json
from pathlib import Path
import numpy as np
import pytest
import torch

from threatweaver.models.classifier import ThreatClassifier, load_checkpoint, save_checkpoint
from threatweaver.models.encoder import ThreatEncoder
from tools.select_embedding_dimension import (
    calculate_utility_scores,
    compute_pareto_frontier,
    DEFAULT_SELECTION_WEIGHTS,
)


def test_encoder_and_classifier_all_candidate_dimensions():
    """Validates that ThreatEncoder and ThreatClassifier instantiate and forward all 6 candidate dimensions."""
    dims = [32, 64, 96, 128, 192, 256]
    x = torch.randn(4, 256)

    for d in dims:
        encoder = ThreatEncoder(input_dim=256, embedding_dim=d)
        latent, emb = encoder(x)
        assert latent.shape == (4, 128)
        assert emb.shape == (4, d)
        # Unit sphere L2 normalization
        norms = torch.norm(emb, p=2, dim=-1)
        assert torch.allclose(norms, torch.ones_like(norms), atol=1e-5)

        classifier = ThreatClassifier(input_dim=256, embedding_dim=d, head_input="embedding")
        assert classifier.embedding_dim == d
        out = classifier(x)
        assert out.logits.shape == (4, 2)
        assert out.probabilities.shape == (4, 2)
        assert out.embeddings.shape == (4, d)
        assert out.latent_features.shape == (4, 128)


def test_gradient_flow_through_embedding_layer():
    """Ensures loss gradients propagate through the embedding projection head to optimize representation."""
    model = ThreatClassifier(input_dim=256, embedding_dim=128, head_input="embedding")
    x = torch.randn(8, 256)
    out = model(x)
    loss = out.logits.sum()
    loss.backward()

    # Both backbone and embedding projection must have non-zero gradients
    assert model.encoder.embedding_proj.weight.grad is not None
    assert model.encoder.embedding_proj.weight.grad.norm().item() > 0.0
    assert model.encoder.backbone[0].weight.grad is not None
    assert model.encoder.backbone[0].weight.grad.norm().item() > 0.0


def test_checkpoint_saving_and_loading_variable_dimensions(tmp_path: Path):
    """Verifies that checkpoints saved with variable dimensions correctly reload with exact shapes and signatures."""
    for dim in [64, 128, 256]:
        model = ThreatClassifier(input_dim=256, embedding_dim=dim, head_input="embedding")
        ckpt_path = tmp_path / f"model_{dim}d.pt"
        save_checkpoint(model=model, save_path=ckpt_path, sign=True)

        assert ckpt_path.is_file()
        assert ckpt_path.with_suffix(".pt.sig").is_file()

        loaded_model, meta = load_checkpoint(ckpt_path)
        assert loaded_model.embedding_dim == dim
        assert meta["embedding_dim"] == dim

        model.eval()
        loaded_model.eval()
        x = torch.randn(2, 256)
        with torch.no_grad():
            orig_out = model(x)
            loaded_out = loaded_model(x)

        assert torch.allclose(orig_out.logits, loaded_out.logits, atol=1e-6)
        assert torch.allclose(orig_out.embeddings, loaded_out.embeddings, atol=1e-6)


def test_pareto_frontier_computation():
    """Validates multi-objective non-dominated sorting logic."""
    candidates = [
        {"dim": 32, "macro_f1": 0.85, "novelty_auroc": 0.50, "forgetting": 0.20, "latency_ms": 0.001, "memory_kb": 100.0},
        {"dim": 64, "macro_f1": 0.87, "novelty_auroc": 0.60, "forgetting": 0.15, "latency_ms": 0.002, "memory_kb": 200.0},
        {"dim": 128, "macro_f1": 0.88, "novelty_auroc": 0.65, "forgetting": 0.12, "latency_ms": 0.003, "memory_kb": 300.0},
        # Dominated candidate (strictly worse than 128 in F1 and novelty, worse in latency and memory)
        {"dim": 96, "macro_f1": 0.86, "novelty_auroc": 0.55, "forgetting": 0.18, "latency_ms": 0.004, "memory_kb": 400.0},
    ]

    pareto_dims, frontier = compute_pareto_frontier(candidates)
    assert 128 in pareto_dims
    assert 64 in pareto_dims
    assert 32 in pareto_dims  # best latency/memory
    assert 96 not in pareto_dims  # dominated by 128 and 64


def test_utility_scoring_and_ranking():
    """Validates normalized multi-attribute utility calculation with configurable weights."""
    candidates = [
        {
            "dim": 64,
            "macro_f1": 0.870,
            "pr_auc": 0.920,
            "detection_rate_at_1pct_fpr": 0.450,
            "novelty_auroc": 0.580,
            "forgetting": 0.150,
            "latency_ms": 0.002,
            "memory_kb": 200.0,
        },
        {
            "dim": 128,
            "macro_f1": 0.885,
            "pr_auc": 0.940,
            "detection_rate_at_1pct_fpr": 0.520,
            "novelty_auroc": 0.650,
            "forgetting": 0.110,
            "latency_ms": 0.0025,
            "memory_kb": 300.0,
        },
    ]

    scored = calculate_utility_scores(candidates, weights=DEFAULT_SELECTION_WEIGHTS)
    assert len(scored) == 2
    # 128 should have highest utility score due to strong F1, PR-AUC, and Novelty AUROC
    assert scored[0]["dim"] == 128
    assert scored[0]["utility_score"] > scored[1]["utility_score"]


def test_ablation_artifacts_integrity():
    """Verifies that generated ablation JSON reports conform to expected research schemas."""
    res_path = Path("artifacts/benchmarks/embedding_dimension_results.json")
    sel_path = Path("artifacts/benchmarks/selected_embedding_dimension.json")
    csv_path = Path("artifacts/benchmarks/embedding_dimension_results.csv")

    assert res_path.is_file(), "embedding_dimension_results.json must exist"
    assert sel_path.is_file(), "selected_embedding_dimension.json must exist"
    assert csv_path.is_file(), "embedding_dimension_results.csv must exist"

    with open(res_path, "r", encoding="utf-8") as f:
        res_data = json.load(f)

    with open(sel_path, "r", encoding="utf-8") as f:
        sel_data = json.load(f)

    # Check all 6 dimensions are documented
    dims = res_data["metadata"]["dimensions_evaluated"]
    assert set(dims) == {32, 64, 96, 128, 192, 256}

    # Verify best dimension was selected and locked
    selected_dim = sel_data["selected_best_dimension"]
    assert selected_dim in dims
    assert "final_untouched_test_results" in sel_data
    assert "macro_f1" in sel_data["final_untouched_test_results"]
    assert sel_data["final_untouched_test_results"]["macro_f1"] > 0.80

    # Verify all 6 checkpoints exist with HMAC signatures
    ckpt_dir = Path("artifacts/checkpoints")
    for d in [32, 64, 96, 128, 192, 256]:
        ckpt = ckpt_dir / f"threatweaver_{d}d.pt"
        sig = ckpt.with_suffix(".pt.sig")
        assert ckpt.is_file(), f"Checkpoint {ckpt.name} must exist"
        assert sig.is_file(), f"Signature {sig.name} must exist"

    # Verify all 9 plots exist
    plots_dir = Path("artifacts/benchmarks/embedding_dimension")
    for plot_idx in range(1, 10):
        matching_plots = list(plots_dir.glob(f"plot{plot_idx}_*.png"))
        assert len(matching_plots) == 1, f"Plot {plot_idx} must exist in {plots_dir}"
