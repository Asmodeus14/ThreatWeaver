"""Isolation guarantees of the extraction worker pool."""

import sys
import threading
import time
from pathlib import Path

import pytest

from threatweaver.sandboxing import ExtractionFailure, ExtractionPool

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def pool():
    p = ExtractionPool(workers=2, timeout_s=10, memory_limit_mb=256, allow_diagnostics=True)
    yield p
    p.close()


def test_real_extraction_in_worker(pool):
    res = pool.run("legacy_features", str(REPO / "samples" / "benign_utility.exe"))
    assert not isinstance(res, ExtractionFailure)
    assert res.is_valid_pe and res.feature_vector.shape == (256,)


def test_timeout_kills_and_replaces_worker(pool):
    t = time.time()
    res = pool.run("_sleep", "30", timeout_s=1.5)
    assert isinstance(res, ExtractionFailure) and res.reason == "timeout"
    assert time.time() - t < 6
    assert pool.run("_sleep", "0") == "slept"  # pool recovered


def test_worker_crash_is_contained(pool):
    res = pool.run("_crash", "")
    assert isinstance(res, ExtractionFailure) and res.reason == "crashed"
    assert pool.run("_sleep", "0") == "slept"


@pytest.mark.skipif(sys.platform != "win32", reason="Job Object memory limits are Windows-only")
def test_memory_limit_enforced(pool):
    res = pool.run("_alloc", "700")  # 700 MB > 256 MB cap
    assert isinstance(res, ExtractionFailure) and res.reason == "memory_limit", res
    assert pool.run("_alloc", "50") == 50  # normal allocations still fine


def test_unknown_task_is_an_error_not_a_crash(pool):
    res = pool.run("no_such_task", "")
    assert isinstance(res, ExtractionFailure) and res.reason == "error"


def test_diagnostic_tasks_disabled_by_default():
    with ExtractionPool(workers=1) as p:
        res = p.run("_sleep", "0")
        assert isinstance(res, ExtractionFailure) and res.reason == "error"


def test_concurrent_callers(pool):
    results = []

    def go():
        results.append(pool.run("legacy_features", str(REPO / "samples" / "suspicious_packed.exe")))

    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 6 and all(not isinstance(r, ExtractionFailure) for r in results)


# ---------------------------------------------------------------------------- engine integration

SHIPPED = REPO / "artifacts" / "checkpoints" / "threatweaver_128d.pt"


def test_isolated_engine_matches_in_process(tmp_path):
    from threatweaver.scanner.inference import InferenceEngine

    sample = REPO / "samples" / "suspicious_packed.exe"
    plain = InferenceEngine(SHIPPED, enable_hash_cache=False, enable_signature_verifier=False)
    iso = InferenceEngine(SHIPPED, enable_hash_cache=False, enable_signature_verifier=False, isolate_extraction=True)
    try:
        a, b = plain.analyze_file(sample), iso.analyze_file(sample)
        assert a.verdict == b.verdict
        assert a.malware_probability == pytest.approx(b.malware_probability, abs=1e-7)
        assert a.evidence_points == b.evidence_points
    finally:
        iso.close()


def test_isolation_timeout_yields_analysis_error_and_is_not_cached(tmp_path):
    from threatweaver.scanner.inference import InferenceEngine, ScanVerdict

    eng = InferenceEngine(SHIPPED, cache_db_path=tmp_path / "c.db", enable_signature_verifier=False,
                          isolate_extraction=True, extraction_timeout_s=0.001)
    try:
        r = eng.analyze_file(REPO / "samples" / "benign_utility.exe")
        assert r.verdict == ScanVerdict.ANALYSIS_ERROR and "timeout" in r.evidence_points[0]
        assert eng.hash_cache.count() == 0
    finally:
        eng.close()
