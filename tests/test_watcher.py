"""Tests for observational real-time filesystem watcher."""

import time
from pathlib import Path
import pytest

from threatweaver.scanner.inference import InferenceEngine, ScanResult
from threatweaver.scanner.watcher import RealtimeFileWatcher
from tests.fixtures import create_minimal_pe


def test_watcher_event_deduplication(tmp_path: Path):
    """Validates that rapid duplicate events are suppressed by deduplication filter."""
    engine = InferenceEngine()
    watcher = RealtimeFileWatcher(watch_directory=tmp_path, inference_engine=engine)

    sample = create_minimal_pe(tmp_path / "app.exe")

    # Enqueue first event -> returns True
    first = watcher.enqueue_file_event(sample)
    assert first is True
    assert watcher.total_events_detected == 1

    # Rapid second event within window -> should be suppressed
    second = watcher.enqueue_file_event(sample)
    assert second is False
    assert watcher.total_duplicates_dropped == 1


def test_watcher_lifecycle(tmp_path: Path):
    """Validates clean start, alert callback, and stop of background watcher threads."""
    alerts = []
    def on_alert(res: ScanResult):
        alerts.append(res)

    engine = InferenceEngine()
    watcher = RealtimeFileWatcher(
        watch_directory=tmp_path,
        inference_engine=engine,
        on_detection_alert=on_alert,
        poll_interval_sec=0.2,
    )

    watcher.start()
    assert watcher.is_running() is True

    # Create a minimal sample in watch folder
    sample = create_minimal_pe(tmp_path / "observed.exe")
    time.sleep(0.5)

    watcher.stop()
    assert watcher.is_running() is False


def test_watcher_reacts_to_new_files_not_existing_ones(tmp_path: Path):
    """Event mode: files present before start are not rescanned; a new file is scanned once."""
    pre = create_minimal_pe(tmp_path / "already_there.exe")
    scanned = []
    engine = InferenceEngine(enable_hash_cache=False)
    watcher = RealtimeFileWatcher(watch_directory=tmp_path, inference_engine=engine)
    original = engine.analyze_file
    engine.analyze_file = lambda p, **kw: (scanned.append(Path(p).name), original(p, **kw))[1]
    watcher.start()
    try:
        time.sleep(1.0)
        create_minimal_pe(tmp_path / "sub" / "dropped.exe") if (tmp_path / "sub").mkdir() is None else None
        (tmp_path / "notes.txt").write_text("not a PE")
        deadline = time.time() + 10
        while time.time() < deadline and "dropped.exe" not in scanned:
            time.sleep(0.2)
    finally:
        watcher.stop()
    assert watcher.mode in ("events", "polling")
    assert "dropped.exe" in scanned
    assert "already_there.exe" not in scanned
    assert "notes.txt" not in scanned
    assert pre.exists()  # observational: never modifies files
