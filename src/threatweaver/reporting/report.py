"""Reporting and scan history management for ThreatWeaver.

Generates structured JSON and Markdown audit reports and maintains a local scan history.
Does not include binary file content in exported reports.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from threatweaver.scanner.inference import ScanResult, ScanVerdict


@dataclass
class ScanSummary:
    """Summary counts of verdicts in a scan session."""
    total_scanned: int = 0
    likely_benign: int = 0
    suspicious: int = 0
    unfamiliar: int = 0
    unsupported: int = 0
    analysis_errors: int = 0


@dataclass
class ScanReport:
    """Complete report of a scanning session."""
    scan_id: str
    target_path: str
    start_time: str
    end_time: str
    duration_seconds: float
    model_version: str
    summary: ScanSummary
    results: List[ScanResult] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        target_path: str,
        start_time: float,
        end_time: float,
        model_version: str,
        results: List[ScanResult],
    ) -> "ScanReport":
        summary = ScanSummary(total_scanned=len(results))
        for r in results:
            if r.verdict == ScanVerdict.LIKELY_BENIGN:
                summary.likely_benign += 1
            elif r.verdict == ScanVerdict.SUSPICIOUS:
                summary.suspicious += 1
            elif r.verdict == ScanVerdict.UNFAMILIAR:
                summary.unfamiliar += 1
            elif r.verdict == ScanVerdict.UNSUPPORTED:
                summary.unsupported += 1
            elif r.verdict == ScanVerdict.ANALYSIS_ERROR:
                summary.analysis_errors += 1

        return cls(
            scan_id=str(uuid.uuid4())[:8],
            target_path=str(target_path),
            start_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
            end_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)),
            duration_seconds=round(end_time - start_time, 2),
            model_version=model_version,
            summary=summary,
            results=results,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Converts report to dictionary excluding internal non-serializable objects."""
        return {
            "scan_id": self.scan_id,
            "target_path": self.target_path,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "model_version": self.model_version,
            "summary": asdict(self.summary),
            "results": [
                {
                    "file_path": r.file_path,
                    "file_name": r.file_name,
                    "file_size_bytes": r.file_size_bytes,
                    "sha256": r.sha256,
                    "verdict": r.verdict.value,
                    "malware_probability": round(r.malware_probability, 4),
                    "novelty_score": round(r.novelty_score, 4),
                    "is_novel": r.is_novel,
                    "evidence_points": r.evidence_points,
                    "scan_duration_ms": round(r.scan_duration_ms, 2),
                    "warning_message": r.warning_message,
                }
                for r in self.results
            ],
        }

    def export_json(self, export_path: str | Path) -> Path:
        """Exports sanitized report to JSON."""
        path = Path(export_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path

    def export_markdown(self, export_path: str | Path) -> Path:
        """Exports report in human-readable Markdown format."""
        path = Path(export_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# ThreatWeaver Scan Report: `{self.scan_id}`",
            "",
            f"- **Target Path**: `{self.target_path}`",
            f"- **Timestamp**: {self.start_time} - {self.end_time} ({self.duration_seconds}s)",
            f"- **Model Version**: {self.model_version}",
            "",
            "## Summary",
            "",
            f"| Metric | Count |",
            "|---|---|",
            f"| Total Scanned | {self.summary.total_scanned} |",
            f"| Likely Benign | {self.summary.likely_benign} |",
            f"| Suspicious | **{self.summary.suspicious}** |",
            f"| Unfamiliar | **{self.summary.unfamiliar}** |",
            f"| Unsupported | {self.summary.unsupported} |",
            f"| Errors | {self.summary.analysis_errors} |",
            "",
            "## Scanned Files Detail",
            "",
            "| File Name | Verdict | Risk Score | SHA-256 | Evidence |",
            "|---|---|---|---|---|",
        ]

        for r in self.results:
            short_sha = r.sha256[:12] + "..." if r.sha256 else "N/A"
            evidence_summary = "; ".join(r.evidence_points[:2]) if r.evidence_points else "None"
            lines.append(
                f"| `{r.file_name}` | **{r.verdict.value}** | {r.malware_probability:.1%} | `{short_sha}` | {evidence_summary} |"
            )

        lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path


class ScanHistoryManager:
    """Stores and retrieves local scan history."""

    def __init__(self, history_file: str | Path = "reports/scan_history.json"):
        self.history_file = Path(history_file).resolve()
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

    def load_history(self) -> List[Dict[str, Any]]:
        if not self.history_file.is_file():
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def record_scan(self, report: ScanReport) -> None:
        """Appends scan report to history log."""
        history = self.load_history()
        summary_record = {
            "scan_id": report.scan_id,
            "target_path": report.target_path,
            "timestamp": report.start_time,
            "duration_seconds": report.duration_seconds,
            "summary": asdict(report.summary),
            "results": [
                {
                    "file_path": r.file_path,
                    "file_name": r.file_name,
                    "file_size_bytes": r.file_size_bytes,
                    "sha256": r.sha256,
                    "verdict": r.verdict.value,
                    "malware_probability": round(r.malware_probability, 4),
                    "novelty_score": round(r.novelty_score, 4),
                    "is_novel": r.is_novel,
                    "evidence_points": r.evidence_points,
                    "scan_duration_ms": round(r.scan_duration_ms, 2),
                    "nearest_known_cluster": r.nearest_known_cluster,
                    "warning_message": r.warning_message,
                }
                for r in report.results[:100]
            ],
        }
        history.append(summary_record)
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
