"""Unit and integration tests for Option A (Instant Prototype Registration)
and Option B (Active Learning & Continual Replay Fine-tuning).
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
import torch

from tests.fixtures import create_minimal_pe
from threatweaver.learning.adaptation_service import (
    AdaptationQueue,
    AdaptationQueueItem,
    AdaptationService,
)
from threatweaver.models.classifier import ThreatClassifier
from threatweaver.models.novelty import NoveltyDetector, PrototypeCluster
from threatweaver.scanner.inference import InferenceEngine, ScanVerdict


def test_novelty_detector_prototype_methods():
    """Validates add_prototype, to_dict_list, and get_prototypes_summary in NoveltyDetector."""
    detector = NoveltyDetector(calibrated_threshold=0.45)
    assert len(detector.prototypes) == 0

    emb = np.random.randn(128).astype(np.float32)
    proto = detector.add_prototype(
        centroid=emb,
        label=1,
        family_name="Test-Ransomware-Alpha",
        sample_count=5,
    )

    assert len(detector.prototypes) == 1
    assert proto.family_name == "Test-Ransomware-Alpha"
    assert proto.label == 1
    assert proto.sample_count == 5
    # Centroid must be unit-normalized
    assert np.isclose(np.linalg.norm(proto.centroid), 1.0, atol=1e-5)

    # Serializations
    dict_list = detector.to_dict_list()
    assert len(dict_list) == 1
    assert dict_list[0]["family_name"] == "Test-Ransomware-Alpha"
    assert len(dict_list[0]["centroid"]) == 128

    summary = detector.get_prototypes_summary()
    assert len(summary) == 1
    assert summary[0]["label_name"] == "Malware"

    # Query with exact vector should have ~0 distance and evaluate as familiar
    assessment = detector.evaluate_novelty(emb)
    assert assessment.is_novel is False
    assert assessment.nearest_family == "Test-Ransomware-Alpha"
    assert assessment.novelty_score < 1e-4


def test_adaptation_queue_lifecycle():
    """Validates enqueue, duplicate deduplication, remove, and status transitions."""
    queue = AdaptationQueue()
    assert len(queue.list_all()) == 0

    # Add sample 1
    item1 = queue.add(
        file_path="C:/threats/sample1.exe",
        file_name="sample1.exe",
        sha256="abc123456",
        assigned_label=1,
        family_name="LockyVariant",
        novelty_score=0.62,
    )
    assert item1.status == "pending"
    assert len(queue.get_pending()) == 1

    # Adding duplicate sha256 updates existing pending item
    item1_dup = queue.add(
        file_path="C:/threats/sample1.exe",
        file_name="sample1.exe",
        sha256="abc123456",
        assigned_label=1,
        family_name="LockyVariantV2",
    )
    assert item1_dup.id == item1.id
    assert item1_dup.family_name == "LockyVariantV2"
    assert len(queue.get_pending()) == 1

    # Add sample 2
    item2 = queue.add(
        file_path="C:/threats/sample2.exe",
        file_name="sample2.exe",
        sha256="def789012",
        assigned_label=0,
        family_name="ValidUtil",
    )
    assert len(queue.get_pending()) == 2

    # Mark item 1 as adapted
    queue.mark_adapted([item1.id])
    assert len(queue.get_pending()) == 1
    assert queue.get_pending()[0].id == item2.id

    # Remove item 2
    removed = queue.remove(item2.id)
    assert removed is True
    assert len(queue.get_pending()) == 0


def test_option_a_instant_prototype_registration(tmp_path: Path):
    """Option A test: registering prototype immediately makes previously unfamiliar file familiar."""
    pe_file = create_minimal_pe(tmp_path / "zero_day.exe", is_64bit=True)

    # Setup initialized engine with small model
    engine = InferenceEngine(checkpoint_path=None)
    engine.model = ThreatClassifier(input_dim=256, num_classes=2, embedding_dim=128)
    engine.model.eval()
    engine.novelty_detector = NoveltyDetector(calibrated_threshold=0.30)
    engine.checkpoint_loaded = True

    adaptation_svc = AdaptationService(engine=engine, replay_seed_data_path=None)

    # Before registration, no prototypes exist -> evaluate_novelty reports unfamiliar
    res_before = engine.analyze_file(pe_file, bypass_cache=True)
    assert res_before.is_novel is True

    # Register instant prototype (Option A)
    reg_res = adaptation_svc.register_instant_prototype(
        file_path=str(pe_file),
        label=1,
        family_name="ZeroDay.CustomCluster",
        persist=False,
    )
    assert reg_res["status"] == "success"
    assert reg_res["family_name"] == "ZeroDay.CustomCluster"
    assert len(engine.novelty_detector.prototypes) == 1

    # Now re-analyzing the same binary: distance is ~0.0, is_novel is False, nearest family is matched!
    res_after = engine.analyze_file(pe_file, bypass_cache=True)
    assert res_after.is_novel is False
    assert res_after.nearest_known_cluster == "ZeroDay.CustomCluster"


def test_option_b_continual_learning_replay(tmp_path: Path):
    """Option B test: continual fine-tuning pass over queued files and replay baseline."""
    pe_file1 = create_minimal_pe(tmp_path / "threat_a.exe", is_64bit=True)
    pe_file2 = create_minimal_pe(tmp_path / "threat_b.exe", is_64bit=True)
    pe_file2.write_bytes(pe_file2.read_bytes() + b"\x90\x90\x90")

    engine = InferenceEngine(checkpoint_path=None)
    engine.model = ThreatClassifier(input_dim=256, num_classes=2, embedding_dim=128)
    engine.model.eval()
    engine.novelty_detector = NoveltyDetector(calibrated_threshold=0.35)
    engine.checkpoint_loaded = True

    adaptation_svc = AdaptationService(engine=engine, replay_seed_data_path="data/ember/ember_sample.jsonl")

    # Enqueue both samples
    adaptation_svc.enqueue_for_continual_learning(
        file_path=str(pe_file1),
        assigned_label=1,
        family_name="Trojan.Variant.A",
        detected_verdict="Unfamiliar",
    )
    adaptation_svc.enqueue_for_continual_learning(
        file_path=str(pe_file2),
        assigned_label=1,
        family_name="Trojan.Variant.B",
        detected_verdict="Unfamiliar",
    )

    assert len(adaptation_svc.queue.get_pending()) == 2

    # Execute continual replay adaptation
    report = adaptation_svc.run_continual_adaptation(
        epochs=3,
        lr=0.001,
        replay_count=10,
        persist=False,
    )

    assert report["status"] == "success"
    assert report["samples_adapted"] == 2
    assert report["replay_samples_used"] > 0
    assert "post_adaptation_new_loss" in report
    assert "catastrophic_forgetting_delta" in report
    assert len(adaptation_svc.queue.get_pending()) == 0
    # Prototypes for new families should have been automatically added
    assert len(engine.novelty_detector.prototypes) >= 2


def test_server_adaptation_api(tmp_path: Path):
    """Validates HTTP API endpoints for learning queue, instant prototype, and adaptation."""
    from http.server import HTTPServer
    from threatweaver.app.server import ThreatWeaverRequestHandler, ScanStateManager
    import urllib.request

    pe_file = create_minimal_pe(tmp_path / "api_test.exe", is_64bit=True)

    engine = InferenceEngine(checkpoint_path=None)
    engine.model = ThreatClassifier(input_dim=256, num_classes=2, embedding_dim=128)
    engine.model.eval()
    engine.novelty_detector = NoveltyDetector(calibrated_threshold=0.40)
    engine.checkpoint_loaded = True

    state_mgr = ScanStateManager(inference_engine=engine)
    adaptation_svc = AdaptationService(engine=engine, replay_seed_data_path=None)

    ThreatWeaverRequestHandler.state_mgr = state_mgr
    ThreatWeaverRequestHandler.engine = engine
    ThreatWeaverRequestHandler.adaptation_svc = adaptation_svc

    # Run ephemeral server on random free port
    httpd = HTTPServer(("127.0.0.1", 0), ThreatWeaverRequestHandler)
    port = httpd.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    import threading
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    try:
        # 1. GET /api/learning/prototypes
        req = urllib.request.Request(f"{base_url}/api/learning/prototypes")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert "prototypes" in data
            assert data["total_prototypes"] == 0

        # 2. POST /api/learning/prototype (Option A)
        payload = json.dumps({
            "file_path": str(pe_file),
            "label": 1,
            "family_name": "API_Malware_Proto",
            "persist": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/learning/prototype",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "success"
            assert data["family_name"] == "API_Malware_Proto"

        # 3. POST /api/learning/queue (Option B enqueue)
        payload = json.dumps({
            "file_path": str(pe_file),
            "label": 1,
            "family_name": "API_Queued_Family",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/learning/queue",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "success"
            assert data["pending_count"] == 1

        # 4. GET /api/learning/queue
        req = urllib.request.Request(f"{base_url}/api/learning/queue")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert len(data["items"]) == 1

        # 5. POST /api/learning/adapt
        adapt_payload = json.dumps({
            "epochs": 2,
            "replay_count": 5,
            "persist": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/learning/adapt",
            data=adapt_payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "success"
            assert data["samples_adapted"] == 1

        # 6. DELETE /api/learning/queue (Clear)
        req = urllib.request.Request(f"{base_url}/api/learning/queue", method="DELETE")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "success"

    finally:
        httpd.shutdown()
        httpd.server_close()
