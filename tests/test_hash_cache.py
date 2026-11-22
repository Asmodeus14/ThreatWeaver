"""Tests for the scan-result cache (keyed by content SHA-256 + engine fingerprint)."""

import os
import tempfile
import threading
from pathlib import Path

from threatweaver.scanner.hash_cache import CleanHashCache
from threatweaver.scanner.inference import InferenceEngine, ScanResult, ScanVerdict
from threatweaver.scanner.scan_service import SYSTEM_SKIP_DIRS, ScanService
from tests.fixtures import create_minimal_pe

FP = "engine-fingerprint-A"


def make_sample_result(path: str, sha256: str = "a" * 64, verdict: ScanVerdict = ScanVerdict.LIKELY_BENIGN) -> ScanResult:
    return ScanResult(
        file_path=path,
        file_name=Path(path).name,
        file_size_bytes=1024,
        sha256=sha256,
        verdict=verdict,
        malware_probability=0.01,
        novelty_score=0.05,
        is_novel=False,
        evidence_points=["Clean baseline"],
        scan_duration_ms=0.5,
        model_version="ThreatWeaver-v1.0",
        nearest_known_cluster="Benign-Cluster-1",
    )


def test_hash_cache_record_and_lookup():
    with tempfile.TemporaryDirectory() as td:
        cache = CleanHashCache(db_path=Path(td) / "cache.db")
        cache.record_scan_result(make_sample_result("C:/test/sample.exe"), FP, source="Unit")
        hit = cache.lookup("a" * 64, FP)
        assert hit is not None and hit.verdict == ScanVerdict.LIKELY_BENIGN
        assert hit.nearest_known_cluster == "Benign-Cluster-1"
        assert cache.hits == 1
        assert cache.lookup("b" * 64, FP) is None          # different bytes
        assert cache.lookup("a" * 64, "other-engine") is None  # different engine
        cache.close()


def test_hit_reports_current_path_for_identical_bytes_elsewhere():
    with tempfile.TemporaryDirectory() as td:
        cache = CleanHashCache(db_path=Path(td) / "cache.db")
        cache.record_scan_result(make_sample_result("C:/a/tool.exe"), FP)
        hit = cache.lookup("a" * 64, FP, file_path="D:/copy/renamed.exe")
        assert hit.file_name == "renamed.exe"
        cache.close()


def test_persistence_across_instances():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "cache.db"
        c1 = CleanHashCache(db_path=db)
        c1.record_scan_result(make_sample_result("C:/x.exe"), FP)
        c1.close()
        c2 = CleanHashCache(db_path=db)
        assert c2.lookup("a" * 64, FP) is not None
        c2.close()


def test_hash_cache_sha256_lookup():
    with tempfile.TemporaryDirectory() as td:
        cache = CleanHashCache(db_path=Path(td) / "cache.db")
        sha = "fedcba9876543210" + "0" * 48
        cache.record_scan_result(make_sample_result("C:/bin/tool.exe", sha256=sha), FP, source="Authenticode")
        hit = cache.lookup_hash(sha)
        assert hit is not None and hit.file_name == "tool.exe"
        cache.close()


def test_hash_cache_ignores_unsupported_and_errors():
    with tempfile.TemporaryDirectory() as td:
        cache = CleanHashCache(db_path=Path(td) / "cache.db")
        cache.record_scan_result(make_sample_result("C:/test/bad.txt", verdict=ScanVerdict.UNSUPPORTED), FP)
        assert cache.count() == 0
        cache.close()


def test_hash_cache_clear_and_count():
    with tempfile.TemporaryDirectory() as td:
        cache = CleanHashCache(db_path=Path(td) / "cache.db")
        for i in range(5):
            cache.record_scan_result(make_sample_result(f"C:/test/prog_{i}.exe", sha256=f"{i}" * 64), FP)
        assert cache.count() == 5
        cache.clear()
        assert cache.count() == 0 and cache.hits == 0
        cache.close()


def test_hash_cache_concurrent_access():
    with tempfile.TemporaryDirectory() as td:
        cache = CleanHashCache(db_path=Path(td) / "cache.db")

        def worker(w_id: int):
            for i in range(20):
                sha = f"{w_id:02x}{i:02x}" * 16
                cache.record_scan_result(make_sample_result(f"C:/t/{w_id}_{i}.exe", sha256=sha), FP)
                cache.lookup(sha, FP)

        threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert cache.count() == 160
        cache.close()


# ---------------------------------------------------------------------------- engine integration


SHIPPED = Path(__file__).resolve().parent.parent / "artifacts" / "checkpoints" / "threatweaver_128d.pt"


def _engine(tmp_path: Path) -> InferenceEngine:
    """Real signed model, so results are produced by the neural tier and are cacheable."""
    eng = InferenceEngine(checkpoint_path=SHIPPED, cache_db_path=tmp_path / "cache.db", enable_signature_verifier=False)
    assert eng.checkpoint_loaded
    return eng


def test_same_size_replacement_with_forged_mtime_is_rescanned(tmp_path: Path):
    """The v0.1 cache returned the old verdict when a file was swapped and its mtime restored."""
    engine = _engine(tmp_path)
    target = create_minimal_pe(tmp_path / "app.exe")
    first = engine.analyze_file(target)
    assert "Cached" not in first.model_version
    assert "Cached" in engine.analyze_file(target).model_version  # precondition: it IS cached
    st = os.stat(target)

    data = bytearray(target.read_bytes())
    data[-1] ^= 0xFF                            # same size, different content
    target.write_bytes(bytes(data))
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))  # attacker restores timestamp

    second = engine.analyze_file(target)
    assert "Cached" not in second.model_version
    assert second.sha256 != first.sha256


def test_unchanged_file_hits_cache(tmp_path: Path):
    engine = _engine(tmp_path)
    target = create_minimal_pe(tmp_path / "app.exe")
    engine.analyze_file(target)
    again = engine.analyze_file(target)
    assert "Cached" in again.model_version


def test_engine_change_invalidates_cache(tmp_path: Path):
    engine = _engine(tmp_path)
    target = create_minimal_pe(tmp_path / "app.exe")
    engine.analyze_file(target)
    before = engine.cache_fingerprint()
    engine.threshold = 0.9                      # any verdict-affecting change
    assert engine.cache_fingerprint() != before
    assert "Cached" not in engine.analyze_file(target).model_version


def test_temp_and_cache_folders_are_scanned(tmp_path: Path):
    for name in ("temp", "tmp", "cache", "inetcache", "installer", "package cache"):
        assert name not in SYSTEM_SKIP_DIRS
    dropped = create_minimal_pe(tmp_path / "Temp" / "dropper.exe")
    service = ScanService(inference_engine=_engine(tmp_path), max_workers=1)
    assert dropped.resolve() in [p.resolve() for p in service.discover_files(tmp_path)]
