"""App-data locations, legacy vault migration and SQLite scan history."""

import json
import os
import time
from pathlib import Path

from threatweaver.core import paths
from threatweaver.quarantine.manager import QuarantineManager
from threatweaver.reporting.report import ScanHistoryManager, ScanReport
from threatweaver.scanner.inference import ScanResult, ScanVerdict
from tests.fixtures import create_minimal_pe


def test_state_lives_under_app_data_not_cwd(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATWEAVER_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    for p in (paths.vault_dir(), paths.cache_dir(), paths.history_db_path().parent, paths.local_models_dir()):
        assert str(p).startswith(str(tmp_path / "home"))
    assert QuarantineManager().quarantine_dir == paths.vault_dir().resolve()
    assert not (tmp_path / "quarantine_store").exists()


def test_resource_root_is_repo_root():
    assert (paths.resource_root() / "pyproject.toml").is_file()


def test_legacy_vault_migration_preserves_and_restores(tmp_path):
    legacy = tmp_path / "quarantine_store"
    old = QuarantineManager(quarantine_dir=legacy, sign_manifest=False)  # v0.1-style unsigned vault
    pe = create_minimal_pe(tmp_path / "suspect.exe")
    original = pe.read_bytes()
    entry = old.quarantine_file(pe)

    target = tmp_path / "appdata_vault"
    target.mkdir()
    res = paths.migrate_legacy_vault(legacy=legacy, target=target)
    assert res["migrated"] and (legacy / "MIGRATED.txt").is_file()
    assert (legacy / f"{entry.quarantine_id}.qf").is_file(), "legacy data is never deleted"
    assert paths.migrate_legacy_vault(legacy=legacy, target=target)["migrated"] is False  # idempotent

    restored = QuarantineManager(quarantine_dir=target).restore_file(entry.quarantine_id)
    assert restored.read_bytes() == original


def _report(n=3, verdict=ScanVerdict.LIKELY_BENIGN):
    results = [ScanResult(file_path=f"C:/x/f{i}.exe", file_name=f"f{i}.exe", file_size_bytes=100, sha256=f"{i:064x}",
                          verdict=verdict, malware_probability=0.1 * i, novelty_score=0.0, is_novel=False,
                          evidence_points=[f"e{i}"], scan_duration_ms=1.0, model_version="m")
               for i in range(n)]
    t = time.time()
    return ScanReport.create("C:/x", t, t + 1, "m", results)


def test_sqlite_history_roundtrip_and_search(tmp_path):
    h = ScanHistoryManager(db_path=tmp_path / "h.db")
    h.record_scan(_report(3))
    h.record_scan(_report(2, ScanVerdict.LIKELY_MALICIOUS))
    hist = h.load_history()
    assert len(hist) == 2 and len(hist[0]["results"]) == 3
    assert hist[1]["summary"]["likely_malicious"] == 2
    assert hist[0]["results"][1]["evidence_points"] == ["e1"]
    hits = h.search_results(verdicts=["Likely Malicious"])
    assert len(hits) == 2 and all(r["verdict"] == "Likely Malicious" for r in hits)
    assert h.load_history(limit=1)[0]["scan_id"] == hist[1]["scan_id"]


def test_legacy_json_history_imported_once(tmp_path):
    legacy = tmp_path / "scan_history.json"
    legacy.write_text(json.dumps([{"scan_id": "old1", "target_path": "C:/", "timestamp": "2026-01-01 00:00:00",
                                   "duration_seconds": 1.0, "summary": {"total_scanned": 1},
                                   "results": [{"file_name": "a.exe", "verdict": "Suspicious", "evidence_points": []}]}]))
    h = ScanHistoryManager(history_file=legacy)
    assert [r["scan_id"] for r in h.load_history()] == ["old1"]
    h2 = ScanHistoryManager(history_file=legacy)
    assert len(h2.load_history()) == 1
