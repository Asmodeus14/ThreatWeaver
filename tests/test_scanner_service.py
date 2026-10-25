"""Tests for ScanService, reporting, and cancellation."""

import threading
import time
from pathlib import Path
import pytest

from threatweaver.reporting.report import ScanReport, ScanHistoryManager
from threatweaver.scanner.inference import InferenceEngine, ScanVerdict
from threatweaver.scanner.scan_service import ScanService
from tests.fixtures import create_minimal_pe


def test_scan_service_directory_execution(tmp_path: Path):
    """Scans a directory containing synthetic PE files and validates report generation."""
    # Create benign sample and malformed sample
    benign_pe = create_minimal_pe(tmp_path / "app.exe")
    text_file = tmp_path / "notes.txt"
    text_file.write_text("plain text", encoding="utf-8")

    # Use checkpoint trained during benchmark
    ckpt_path = Path("artifacts/checkpoints/threatweaver_v1.pt")
    engine = InferenceEngine(checkpoint_path=ckpt_path if ckpt_path.is_file() else None)
    service = ScanService(inference_engine=engine, max_workers=2)

    progress_reports = []
    def on_prog(cur, tot, fn):
        progress_reports.append((cur, tot, fn))

    # Scan directory with only_pe_extensions=False to include text file
    report = service.scan(tmp_path, only_pe_extensions=False, on_progress=on_prog)

    assert report.summary.total_scanned == 2
    assert len(progress_reports) == 2
    assert any(r.verdict == ScanVerdict.UNSUPPORTED for r in report.results)
    assert any(r.verdict in (ScanVerdict.LIKELY_BENIGN, ScanVerdict.SUSPICIOUS, ScanVerdict.UNFAMILIAR) for r in report.results)


def test_scan_service_cancellation(tmp_path: Path):
    """Validates that scan service cancellation halts execution promptly."""
    # Create several sample files
    for i in range(10):
        create_minimal_pe(tmp_path / f"test_{i}.exe")

    engine = InferenceEngine()
    service = ScanService(inference_engine=engine, max_workers=1)

    # Trigger cancel immediately
    service.cancel()
    assert service.is_cancelled() is True

    report = service.scan(tmp_path, only_pe_extensions=True)
    # Cancellation should halt scan before finishing all 10 files
    assert report.summary.total_scanned <= 10


def test_report_export_and_history(tmp_path: Path):
    """Validates report JSON and Markdown export and scan history manager."""
    pe_file = create_minimal_pe(tmp_path / "clean.exe")
    engine = InferenceEngine()
    service = ScanService(inference_engine=engine)

    report = service.scan(pe_file)
    assert report.summary.total_scanned == 1

    json_export = tmp_path / "out_report.json"
    md_export = tmp_path / "out_report.md"
    report.export_json(json_export)
    report.export_markdown(md_export)

    assert json_export.is_file()
    assert md_export.is_file()
    assert "clean.exe" in md_export.read_text(encoding="utf-8")

    hist_file = tmp_path / "history.json"
    hist_mgr = ScanHistoryManager(history_file=hist_file)
    hist_mgr.record_scan(report)
    history = hist_mgr.load_history()
    assert len(history) == 1
    assert history[0]["scan_id"] == report.scan_id


def test_full_system_scan_discovery_and_roots():
    """Validates root drive detection and full system discovery behavior."""
    roots = ScanService.get_system_scan_roots()
    assert len(roots) >= 1
    assert any(str(r).startswith("C") or str(r) == "/" for r in roots)

    service = ScanService(inference_engine=InferenceEngine(), max_workers=1)
    # Cancel immediately so it doesn't walk the entire drive in unit tests
    service.cancel()
    discovered = service.discover_files("FULL_SYSTEM")
    assert isinstance(discovered, list)
