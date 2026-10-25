"""Tests for ThreatWeaver models, embeddings, and novelty detection."""

import numpy as np
import pytest
import torch
from pathlib import Path

from threatweaver.models.classifier import ThreatClassifier, load_checkpoint, save_checkpoint
from threatweaver.models.encoder import ThreatEncoder
from threatweaver.models.novelty import NoveltyDetector


def test_encoder_forward():
    """Validates encoder output shapes and L2 unit sphere normalization."""
    encoder = ThreatEncoder(input_dim=256, hidden_dims=[128, 64], embedding_dim=32)
    x = torch.randn(8, 256)
    latent, embs = encoder(x)

    assert latent.shape == (8, 64)
    assert embs.shape == (8, 32)
    # Norm of embeddings should be 1.0
    norms = torch.norm(embs, p=2, dim=-1)
    assert torch.allclose(norms, torch.ones_like(norms), atol=1e-5)


def test_classifier_forward_and_probabilities():
    """Validates classification head output and calibrated probability sum."""
    model = ThreatClassifier(input_dim=256, num_classes=2)
    x = torch.randn(4, 256)
    out = model(x)

    assert out.logits.shape == (4, 2)
    assert out.probabilities.shape == (4, 2)
    # Probabilities must sum to 1.0 across classes
    prob_sums = torch.sum(out.probabilities, dim=-1)
    assert torch.allclose(prob_sums, torch.ones_like(prob_sums), atol=1e-5)


def test_save_and_load_checkpoint(tmp_path: Path):
    """Validates safe serialization and deserialization with schema validation."""
    model = ThreatClassifier(input_dim=256, num_classes=2)
    ckpt_path = tmp_path / "model.pt"

    mean_vec = [0.1] * 256
    std_vec = [1.0] * 256

    save_checkpoint(
        model=model,
        save_path=ckpt_path,
        feature_mean=mean_vec,
        feature_std=std_vec,
        novelty_threshold=0.45,
    )

    # Verify signature file was created
    assert ckpt_path.with_suffix(".pt.sig").is_file()

    loaded_model, meta = load_checkpoint(ckpt_path, device="cpu")
    assert meta["schema_version"] == "1.0"
    assert meta["novelty_threshold"] == 0.45
    assert len(meta["feature_mean"]) == 256

    # Verify predictions match exactly
    model.eval()
    test_x = torch.randn(2, 256)
    with torch.no_grad():
        out1 = model(test_x)
        out2 = loaded_model(test_x)
    assert torch.allclose(out1.logits, out2.logits, atol=1e-6)


def test_checkpoint_tamper_detection(tmp_path: Path):
    """Verifies that tampering with checkpoint payload causes HMAC integrity failure."""
    model = ThreatClassifier(input_dim=256, num_classes=2)
    ckpt_path = tmp_path / "tampered.pt"

    save_checkpoint(model=model, save_path=ckpt_path)
    sig_path = ckpt_path.with_suffix(".pt.sig")
    assert sig_path.is_file()

    # Tamper with checkpoint bytes
    with open(ckpt_path, "r+b") as f:
        f.seek(10)
        original_byte = f.read(1)
        f.seek(10)
        f.write(bytes([(original_byte[0] ^ 0xFF)]))

    with pytest.raises(ValueError, match="integrity verification failed"):
        load_checkpoint(ckpt_path)


def test_checkpoint_signature_mismatch(tmp_path: Path):
    """Verifies that an invalid signature causes load_checkpoint to fail."""
    model = ThreatClassifier(input_dim=256, num_classes=2)
    ckpt_path = tmp_path / "bad_sig.pt"

    save_checkpoint(model=model, save_path=ckpt_path)
    sig_path = ckpt_path.with_suffix(".pt.sig")
    sig_path.write_text("0000000000000000000000000000000000000000000000000000000000000000")

    with pytest.raises(ValueError, match="integrity verification failed"):
        load_checkpoint(ckpt_path)


def test_unsigned_checkpoint_warning(tmp_path: Path):
    """Verifies that loading an unsigned checkpoint emits a warning."""
    model = ThreatClassifier(input_dim=256, num_classes=2)
    ckpt_path = tmp_path / "unsigned.pt"

    save_checkpoint(model=model, save_path=ckpt_path, sign=False)
    sig_path = ckpt_path.with_suffix(".pt.sig")
    assert not sig_path.exists()

    with pytest.warns(UserWarning, match="Loading unsigned checkpoint"):
        loaded, _ = load_checkpoint(ckpt_path)
        assert loaded is not None


def test_novelty_detector_calibration_and_evaluation():
    """Validates novelty threshold calibration and novelty evaluation."""
    detector = NoveltyDetector(distance_metric="cosine")

    # Generate two tight clusters in 32-dim space
    cluster1 = np.random.randn(20, 32).astype(np.float32)
    cluster1 = cluster1 / np.linalg.norm(cluster1, axis=-1, keepdims=True)
    labels = np.array([0] * 10 + [1] * 10)

    detector.fit_prototypes(cluster1, labels)
    assert len(detector.prototypes) > 0

    # Calibrate on held-out validation points with small noise
    val_points = cluster1[:5] + np.random.normal(0, 0.05, size=(5, 32)).astype(np.float32)
    val_points = val_points / np.linalg.norm(val_points, axis=-1, keepdims=True)
    threshold = detector.calibrate_threshold(val_points, percentile=90.0)
    assert threshold > 0.0


    # Known sample should be assessed as Familiar
    known_sample = cluster1[0]
    assessment_known = detector.evaluate_novelty(known_sample)
    assert assessment_known.is_novel is False
    assert assessment_known.status_label == "Familiar"

    # Distant orthogonal sample should be assessed as Unfamiliar / Novel
    distant_sample = -cluster1[0]  # opposite side of unit sphere
    assessment_distant = detector.evaluate_novelty(distant_sample)
    assert assessment_distant.is_novel is True
    assert assessment_distant.status_label == "Unfamiliar"
