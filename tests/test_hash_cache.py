"""Tests for CleanHashCache (Tier 0 triage engine)."""

import tempfile
import threading
from pathlib import Path

from threatweaver.scanner.hash_cache import CleanHashCache
from threatweaver.scanner.inference import ScanResult, ScanVerdict


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
    )


def test_hash_cache_record_and_lookup():
    """Validates basic cache insertion and hit verification."""
    with tempfile.TemporaryDirectory() as td:
        db_file = Path(td) / "cache.db"
        cache = CleanHashCache(db_path=db_file)

        res = make_sample_result("C:/test/sample.exe")
        cache.record_scan_result(res, mtime=1000.0, source="Unit")

        # Hit by path + valid mtime + size
        hit = cache.lookup_file("C:/test/sample.exe", mtime=1000.0, file_size=1024)
        assert hit is not None
        assert hit.verdict == ScanVerdict.LIKELY_BENIGN
        assert hit.sha256 == "a" * 64
        assert cache.hits == 1

        # Miss by altered mtime
        miss_mtime = cache.lookup_file("C:/test/sample.exe", mtime=2000.0, file_size=1024)
        assert miss_mtime is None

        # Miss by altered size
        miss_size = cache.lookup_file("C:/test/sample.exe", mtime=1000.0, file_size=2048)
        assert miss_size is None

        cache.close()


def test_hash_cache_sha256_lookup():
    """Validates secondary lookup by SHA-256 hash."""
    with tempfile.TemporaryDirectory() as td:
        db_file = Path(td) / "cache.db"
        cache = CleanHashCache(db_path=db_file)

        sha = "fedcba9876543210" + "0" * 48
        res = make_sample_result("C:/bin/tool.exe", sha256=sha)
        cache.record_scan_result(res, mtime=500.0, source="Authenticode")

        hit = cache.lookup_hash(sha)
        assert hit is not None
        assert hit.file_name == "tool.exe"
        assert hit.verdict == ScanVerdict.LIKELY_BENIGN

        cache.close()


def test_hash_cache_ignores_unsupported_and_errors():
    """Validates that error results are never cached."""
    with tempfile.TemporaryDirectory() as td:
        db_file = Path(td) / "cache.db"
        cache = CleanHashCache(db_path=db_file)

        err_res = make_sample_result("C:/test/bad.txt", verdict=ScanVerdict.UNSUPPORTED)
        cache.record_scan_result(err_res, mtime=100.0)

        assert cache.count() == 0
        hit = cache.lookup_file("C:/test/bad.txt", mtime=100.0, file_size=1024)
        assert hit is None

        cache.close()


def test_hash_cache_clear_and_count():
    """Validates clearing cache."""
    with tempfile.TemporaryDirectory() as td:
        db_file = Path(td) / "cache.db"
        cache = CleanHashCache(db_path=db_file)

        for i in range(5):
            res = make_sample_result(f"C:/test/prog_{i}.exe", sha256=f"{i}" * 64)
            cache.record_scan_result(res, mtime=100.0)

        assert cache.count() == 5
        cache.clear()
        assert cache.count() == 0
        assert cache.hits == 0

        cache.close()


def test_hash_cache_concurrent_access():
    """Validates thread safety across concurrent readers and writers."""
    with tempfile.TemporaryDirectory() as td:
        db_file = Path(td) / "cache.db"
        cache = CleanHashCache(db_path=db_file)

        def worker(w_id: int):
            for i in range(20):
                path = f"C:/test/thread_{w_id}_{i}.exe"
                res = make_sample_result(path, sha256=f"{w_id:02x}{i:02x}" * 16)
                cache.record_scan_result(res, mtime=float(i))
                cache.lookup_file(path, mtime=float(i), file_size=1024)

        threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert cache.count() == 160
        cache.close()
