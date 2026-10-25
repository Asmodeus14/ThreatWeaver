"""ThreatWeaver multi-threaded scan service with cancellation and streaming progress."""

from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, List, Optional, Set

if TYPE_CHECKING:
    from threatweaver.reporting.report import ScanReport
from threatweaver.scanner.inference import InferenceEngine, ScanResult, ScanVerdict


PE_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".drv"
}

SYSTEM_SKIP_DIRS: Set[str] = {
    "$recycle.bin",
    "system volume information",
    "winsxs",
    "servicing",
    "softwaredistribution",
    "driverstore",
    "package cache",
    "installer",
    "temp",
    "tmp",
    "cache",
    "caches",
    "inetcache",
    "assembly",
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".cargo",
    ".rustup",
    ".gradle",
}


class ScanService:
    """Orchestrates file and directory scans with concurrency and responsive cancellation."""

    def __init__(
        self,
        inference_engine: InferenceEngine,
        max_workers: int = 4,
    ):
        self.engine = inference_engine
        self.max_workers = max_workers
        self._cancel_requested = threading.Event()

    def cancel(self) -> None:
        """Requests immediate cancellation of ongoing scan."""
        self._cancel_requested.set()

    def is_cancelled(self) -> bool:
        return self._cancel_requested.is_set()

    @staticmethod
    def get_system_scan_roots() -> List[Path]:
        """Detects available system root paths or fixed drives on host."""
        roots: List[Path] = []
        if os.name == "nt":
            for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                drive = Path(f"{letter}:\\")
                if drive.exists():
                    roots.append(drive)
            if not roots:
                roots.append(Path("C:\\"))
        else:
            roots.append(Path("/"))
        return roots

    def _walk_generator(self, target_dir: Path, only_pe_extensions: bool = True) -> Iterable[Path]:
        try:
            for root, dirs, files in os.walk(target_dir, topdown=True, onerror=None):
                if self._cancel_requested.is_set():
                    break
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in SYSTEM_SKIP_DIRS
                ]
                for f in files:
                    if self._cancel_requested.is_set():
                        break
                    p = Path(root) / f
                    if only_pe_extensions:
                        if p.suffix.lower() in PE_EXTENSIONS:
                            yield p
                    else:
                        yield p
        except Exception:
            pass

    def iter_files(
        self, target_path: str | Path | List[str | Path], only_pe_extensions: bool = True
    ) -> Iterable[Path]:
        """Streams candidate files lazily without blocking traversal."""
        if isinstance(target_path, str) and target_path.strip().upper() in ("FULL_SYSTEM", "SYSTEM"):
            roots = self.get_system_scan_roots()
            for root in roots:
                if self._cancel_requested.is_set():
                    break
                # If Windows C: drive, walk prioritized executable attack surfaces first
                if os.name == "nt" and str(root).upper().startswith("C"):
                    subdirs = [
                        root / "Windows",
                        root / "Program Files",
                        root / "Program Files (x86)",
                        root / "ProgramData",
                        root / "Users",
                    ]
                    for sub in subdirs:
                        if self._cancel_requested.is_set():
                            break
                        if sub.exists():
                            yield from self._walk_generator(sub, only_pe_extensions=only_pe_extensions)
                    # Also yield any root-level executables on C:\
                    try:
                        for entry in os.scandir(root):
                            if entry.is_file():
                                p = Path(entry.path)
                                if (not only_pe_extensions) or (p.suffix.lower() in PE_EXTENSIONS):
                                    yield p
                    except Exception:
                        pass
                else:
                    yield from self._walk_generator(root, only_pe_extensions=only_pe_extensions)
            return

        if isinstance(target_path, list):
            for item in target_path:
                if self._cancel_requested.is_set():
                    break
                p = Path(str(item).strip().strip("'\"")).expanduser().resolve()
                if p.is_file():
                    yield p
                elif p.is_dir():
                    yield from self._walk_generator(p, only_pe_extensions=only_pe_extensions)
            return

        clean = Path(str(target_path).strip().strip("'\"")).expanduser().resolve()
        if clean.is_file():
            yield clean
            return

        yield from self._walk_generator(clean, only_pe_extensions=only_pe_extensions)

    def discover_files(
        self, target_path: str | Path | List[str | Path], only_pe_extensions: bool = True
    ) -> List[Path]:
        """Discovers files in target path, system drives, or multiple paths."""
        return list(self.iter_files(target_path, only_pe_extensions=only_pe_extensions))

    def scan(
        self,
        target_path: str | Path,
        only_pe_extensions: bool = True,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
        on_result: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanReport:
        """Executes streaming scan across target file or folder with real-time callbacks."""
        from threatweaver.reporting.report import ScanReport


        start_t = time.time()
        clean_str = str(target_path).strip().strip("'\"")
        is_full_system = clean_str.upper() in ("FULL_SYSTEM", "SYSTEM")
        target_display = "Full System (All Drives)" if is_full_system else str(clean_str)

        if self._cancel_requested.is_set():
            self._cancel_requested.clear()
            end_t = time.time()
            return ScanReport.create(
                target_path=target_display,
                start_time=start_t,
                end_time=end_t,
                model_version=self.engine.model_version,
                results=[],
            )

        self._cancel_requested.clear()

        file_queue: queue.Queue[Optional[Path]] = queue.Queue(maxsize=512)
        discovered_count = 0
        completed_count = 0
        discovery_done = threading.Event()
        results: List[ScanResult] = []
        lock = threading.Lock()

        def producer():
            nonlocal discovered_count
            try:
                for fpath in self.iter_files(target_path, only_pe_extensions=only_pe_extensions):
                    if self._cancel_requested.is_set():
                        break
                    with lock:
                        discovered_count += 1
                    while not self._cancel_requested.is_set():
                        try:
                            file_queue.put(fpath, timeout=0.1)
                            break
                        except queue.Full:
                            continue
            finally:
                discovery_done.set()

        producer_thread = threading.Thread(target=producer, daemon=True)
        producer_thread.start()

        def worker():
            nonlocal completed_count
            while not self._cancel_requested.is_set():
                try:
                    fpath = file_queue.get(timeout=0.1)
                except queue.Empty:
                    if discovery_done.is_set() and file_queue.empty():
                        break
                    continue

                try:
                    res = self.engine.analyze_file(fpath)
                    with lock:
                        results.append(res)
                        completed_count += 1
                        cur = completed_count
                        tot = max(discovered_count, cur)
                    if on_progress:
                        on_progress(cur, tot, res.file_name)
                    if on_result:
                        on_result(res)
                except Exception as e:
                    file_p = Path(fpath)
                    err_res = ScanResult(
                        file_path=str(file_p),
                        file_name=file_p.name,
                        file_size_bytes=0,
                        sha256="",
                        verdict=ScanVerdict.ANALYSIS_ERROR,
                        malware_probability=0.0,
                        novelty_score=0.0,
                        is_novel=False,
                        evidence_points=[f"Scanning worker exception: {str(e)}"],
                        scan_duration_ms=0.0,
                        model_version=self.engine.model_version,
                        warning_message=str(e),
                    )
                    with lock:
                        results.append(err_res)
                        completed_count += 1
                        cur = completed_count
                        tot = max(discovered_count, cur)
                    if on_progress:
                        on_progress(cur, tot, file_p.name)
                finally:
                    file_queue.task_done()

        workers: List[threading.Thread] = []
        for _ in range(self.max_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)

        producer_thread.join()
        for t in workers:
            t.join()

        end_t = time.time()
        return ScanReport.create(
            target_path=target_display,
            start_time=start_t,
            end_time=end_t,
            model_version=self.engine.model_version,
            results=results,
        )
