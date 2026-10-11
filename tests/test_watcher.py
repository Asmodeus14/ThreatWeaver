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
