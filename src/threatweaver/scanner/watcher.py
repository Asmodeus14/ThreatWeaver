"""Observational, non-blocking real-time filesystem watcher for ThreatWeaver.

Provides user-mode file change monitoring with event deduplication and storm throttling.
STRICT SAFETY GUARANTEE: Does not block system I/O, does not disable Windows security controls,
and operates in an observational monitoring mode only.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Set

from threatweaver.scanner.inference import InferenceEngine, ScanResult, ScanVerdict
from threatweaver.scanner.scan_service import PE_EXTENSIONS

DEDUPLICATION_WINDOW_SEC = 2.0  # Time window to suppress duplicate change events
MAX_EVENT_QUEUE_SIZE = 1000


@dataclass
class WatcherEvent:
    """Represents a file modification/creation event detected on disk."""
    file_path: Path
    timestamp: float
    event_type: str = "MODIFIED"


class RealtimeFileWatcher:
    """Non-blocking observational filesystem monitor with event deduplication."""

    def __init__(
        self,
        watch_directory: str | Path,
        inference_engine: InferenceEngine,
        on_detection_alert: Optional[Callable[[ScanResult], None]] = None,
        poll_interval_sec: float = 1.0,
    ):
        self.watch_dir = Path(watch_directory).resolve()
        self.engine = inference_engine
        self.on_alert = on_detection_alert
        self.poll_interval = poll_interval_sec

        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._watcher_thread: Optional[threading.Thread] = None
        self._event_queue: queue.Queue[WatcherEvent] = queue.Queue(maxsize=MAX_EVENT_QUEUE_SIZE)

        # Deduplication cache: maps str(path) -> last_seen_timestamp
        self._recent_events: OrderedDict[str, float] = OrderedDict()
        self._recent_lock = threading.Lock()

        # Telemetry metrics
        self.total_events_detected = 0
        self.total_events_scanned = 0
        self.total_duplicates_dropped = 0
        self.queue_overflow_drops = 0

    def start(self) -> None:
        """Starts background monitoring and analysis threads."""
        self._stop_event.clear()
        self._watcher_thread = threading.Thread(
            target=self._monitor_loop, name="ThreatWeaver-Watcher", daemon=True
        )
        self._worker_thread = threading.Thread(
            target=self._processing_loop, name="ThreatWeaver-Worker", daemon=True
        )
        self._watcher_thread.start()
        self._worker_thread.start()

    def stop(self) -> None:
        """Stops background threads cleanly."""
        self._stop_event.set()
        if self._watcher_thread and self._watcher_thread.is_alive():
            self._watcher_thread.join(timeout=2.0)
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

    def is_running(self) -> bool:
        return not self._stop_event.is_set() and (
            (self._watcher_thread is not None and self._watcher_thread.is_alive())
        )

    def _should_suppress_duplicate(self, file_path_str: str, now: float) -> bool:
        """Throttles event storms by dropping events within DEDUPLICATION_WINDOW_SEC."""
        with self._recent_lock:
            # Purge expired entries
            cutoff = now - DEDUPLICATION_WINDOW_SEC
            while self._recent_events and next(iter(self._recent_events.values())) < cutoff:
                self._recent_events.popitem(last=False)

            if file_path_str in self._recent_events:
                self._recent_events[file_path_str] = now
                self.total_duplicates_dropped += 1
                return True

            self._recent_events[file_path_str] = now
            return False

    def enqueue_file_event(self, path: Path) -> bool:
        """Manually or programmatically enqueues a file change event."""
        if path.suffix.lower() not in PE_EXTENSIONS:
            return False

        now = time.time()
        path_str = str(path.resolve())
        if self._should_suppress_duplicate(path_str, now):
            return False

        self.total_events_detected += 1
        event = WatcherEvent(file_path=path, timestamp=now)
        try:
            self._event_queue.put_nowait(event)
            return True
        except queue.Full:
            self.queue_overflow_drops += 1
            return False

    def _monitor_loop(self) -> None:
        """Polling monitor loop scanning directory state for new/modified PE files."""
        known_mtimes: Dict[str, float] = {}

        while not self._stop_event.is_set():
            try:
                if self.watch_dir.is_dir():
                    for root, _, files in os.walk(self.watch_dir):
                        if self._stop_event.is_set():
                            break
                        for f in files:
                            p = Path(root) / f
                            if p.suffix.lower() in PE_EXTENSIONS:
                                try:
                                    mtime = p.stat().st_mtime
                                    p_str = str(p)
                                    if p_str not in known_mtimes or known_mtimes[p_str] != mtime:
                                        known_mtimes[p_str] = mtime
                                        self.enqueue_file_event(p)
                                except Exception:
                                    pass
            except Exception:
                pass

            self._stop_event.wait(self.poll_interval)

    def _processing_loop(self) -> None:
        """Processes enqueued change events through static inference engine."""
        while not self._stop_event.is_set():
            try:
                event = self._event_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                # Analyze file statically without blocking file access
                if event.file_path.is_file():
                    res = self.engine.analyze_file(event.file_path)
                    self.total_events_scanned += 1
                    # In observational mode, notify if suspicious or unfamiliar
                    if res.verdict in (ScanVerdict.SUSPICIOUS, ScanVerdict.UNFAMILIAR):
                        if self.on_alert:
                            self.on_alert(res)
            except Exception:
                pass
            finally:
                self._event_queue.task_done()
