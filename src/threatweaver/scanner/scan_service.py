"""ThreatWeaver multi-threaded scan service with cancellation and streaming progress."""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, List, Optional, Set

if TYPE_CHECKING:
    from threatweaver.reporting.report import ScanReport
from threatweaver.scanner.inference import InferenceEngine, ScanResult, ScanVerdict


PE_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".drv"
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

    def discover_files(
        self, target_path: Path, only_pe_extensions: bool = True
    ) -> List[Path]:
        """Discovers files in target path without loading file contents into memory."""
        if target_path.is_file():
            return [target_path]

        discovered: List[Path] = []
        try:
            for root, _, files in os.walk(target_path):
                if self._cancel_requested.is_set():
                    break
                for f in files:
                    p = Path(root) / f
                    if only_pe_extensions:
                        if p.suffix.lower() in PE_EXTENSIONS:
                            discovered.append(p)
                    else:
                        discovered.append(p)
        except Exception:
            pass

        return discovered

    def scan(
        self,
        target_path: str | Path,
        only_pe_extensions: bool = True,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
        on_result: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanReport:
        """Executes scan across target file or folder with progress callbacks."""
        from threatweaver.reporting.report import ScanReport

        self._cancel_requested.clear()
        start_t = time.time()
        path = Path(target_path).resolve()


        candidate_files = self.discover_files(path, only_pe_extensions=only_pe_extensions)
        total_files = len(candidate_files)
        results: List[ScanResult] = []

        if total_files == 0:
            end_t = time.time()
            return ScanReport.create(
                target_path=str(path),
                start_time=start_t,
                end_time=end_t,
                model_version=self.engine.model_version,
                results=[],
            )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit batches of work
            future_to_file = {
                executor.submit(self.engine.analyze_file, file_path): file_path
                for file_path in candidate_files
            }

            completed_count = 0
            for future in as_completed(future_to_file):
                if self._cancel_requested.is_set():
                    # Drain remaining futures without waiting
                    break

                try:
                    res = future.result()
                    results.append(res)
                    completed_count += 1
                    if on_progress:
                        on_progress(completed_count, total_files, res.file_name)
                    if on_result:
                        on_result(res)
                except Exception as e:
                    file_p = future_to_file[future]
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
                    results.append(err_res)
                    completed_count += 1
                    if on_progress:
                        on_progress(completed_count, total_files, file_p.name)

        end_t = time.time()
        return ScanReport.create(
            target_path=str(path),
            start_time=start_t,
            end_time=end_t,
            model_version=self.engine.model_version,
            results=results,
        )
