"""Overview aggregates come only from real scan history (/api/insights)."""
from threatweaver.reporting.report import ScanHistoryManager


def _scan(mgr, sid, created_day, results):
    mgr._insert({
        "scan_id": sid, "target_path": "C:/x", "timestamp": f"{created_day} 10:00:00", "duration_seconds": 1.0,
        "model_version": "m", "summary": {"total_scanned": len(results)}, "results": results,
    })


def _r(sha, verdict, p, mv="lgbm-v3-win64-dotnet (LightGBM, EMBER v3)"):
    return {"file_path": f"C:/x/{sha}.exe", "file_name": f"{sha}.exe", "sha256": sha, "verdict": verdict,
            "malware_probability": p, "model_version": mv}


def test_insights_counts_each_file_once_at_latest_verdict(tmp_path):
    mgr = ScanHistoryManager(db_path=tmp_path / "h.db")
    _scan(mgr, "s1", "2026-11-01", [_r("a", "Suspicious", 0.9), _r("b", "Likely Benign", 0.1)])
    _scan(mgr, "s2", "2026-11-02", [_r("a", "Likely Benign", 0.2), _r("c", "Likely Malicious", 0.99)])
    d = mgr.insights(model_id="lgbm-v3-win64-dotnet", bins=10)
    assert d["unique_files"] == 3
    assert d["verdict_counts"] == {"Likely Benign": 2, "Likely Malicious": 1}
    # score histogram: a=0.2 (bin 2), b=0.1 (bin 1), c=0.99 (bin 9)
    assert d["score_histogram"]["n"] == 3
    assert [i for i, v in enumerate(d["score_histogram"]["counts"]) if v] == [1, 2, 9]
    assert d["score_histogram"]["by_verdict"]["Likely Malicious"][9] == 1
    assert sum(d["score_histogram"]["by_verdict"]["Likely Benign"]) == 2
    assert d["daily"] == [
        {"day": "2026-11-01", "scanned": 2, "flagged": 1},
        {"day": "2026-11-02", "scanned": 2, "flagged": 1},
    ]


def test_insights_histogram_excludes_other_detectors(tmp_path):
    mgr = ScanHistoryManager(db_path=tmp_path / "h.db")
    _scan(mgr, "s1", "2026-11-01", [
        _r("a", "Likely Benign", 0.1, mv="ThreatWeaver-v1.0"),
        _r("b", "Likely Benign", 0.1, mv="lgbm-v3-dotnet (LightGBM, EMBER v3)"),
        _r("c", "Likely Benign", 0.1, mv="Cached (lgbm-v3-win64-dotnet (LightGBM, EMBER v3))"),
    ])
    d = mgr.insights(model_id="lgbm-v3-win64-dotnet")
    assert d["unique_files"] == 3
    assert d["score_histogram"]["n"] == 1  # only the cached result of the active detector


def test_insights_empty_history(tmp_path):
    d = ScanHistoryManager(db_path=tmp_path / "h.db").insights(model_id=None)
    assert d["unique_files"] == 0 and d["daily"] == [] and d["score_histogram"]["n"] == 0


def test_unscored_files_are_not_plotted(tmp_path):
    mgr = ScanHistoryManager(db_path=tmp_path / "h.db")
    _scan(mgr, "s1", "2026-11-01", [_r("a", "Analysis Error", 0.0), _r("b", "Unsupported Format", 0.0),
                                    _r("c", "Likely Benign", 0.05)])
    d = mgr.insights(model_id="lgbm-v3-win64-dotnet")
    assert d["unique_files"] == 3
    assert d["score_histogram"]["n"] == 1
    assert set(d["score_histogram"]["by_verdict"]) == {"Likely Benign"}
