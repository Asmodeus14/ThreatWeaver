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
    trusted_signer: int = 0
    known_malicious: int = 0
    likely_malicious: int = 0
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
            elif r.verdict == ScanVerdict.TRUSTED_SIGNER:
                summary.trusted_signer += 1
            elif r.verdict == ScanVerdict.KNOWN_MALICIOUS:
                summary.known_malicious += 1
            elif r.verdict == ScanVerdict.LIKELY_MALICIOUS:
                summary.likely_malicious += 1
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
            f"| Known Malicious | **{self.summary.known_malicious}** |",
            f"| Likely Malicious | **{self.summary.likely_malicious}** |",
            f"| Suspicious | **{self.summary.suspicious}** |",
            f"| Trusted Signer | **{self.summary.trusted_signer}** |",
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
    """Scan history in SQLite (WAL). Same API/shape as the v0.1 JSON file, without rewriting
    the whole history on every scan. A legacy reports/scan_history.json is imported once."""

    def __init__(self, history_file: Optional[str | Path] = None, db_path: Optional[str | Path] = None):
        from threatweaver.core import paths

        legacy: Optional[Path] = None
        if db_path is None and history_file:
            db_path, legacy = Path(history_file).with_suffix(".db"), Path(history_file)
        elif db_path is None:
            # Default per-user database: import the v0.1 repo-local history once.
            db_path, legacy = paths.history_db_path(), paths.resource_path("reports/scan_history.json")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()
        if legacy is not None and legacy.suffix == ".json":
            self._import_legacy_json(legacy)

    def _connect(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _init(self) -> None:
        with self._connect() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY, target_path TEXT, timestamp TEXT, duration_seconds REAL,
                    model_version TEXT, summary TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS results (
                    scan_id TEXT NOT NULL, idx INTEGER NOT NULL, file_path TEXT, file_name TEXT, file_size_bytes INTEGER,
                    sha256 TEXT, verdict TEXT, malware_probability REAL, novelty_score REAL, is_novel INTEGER,
                    evidence TEXT, scan_duration_ms REAL, model_version TEXT, warning_message TEXT,
                    PRIMARY KEY (scan_id, idx));
                CREATE INDEX IF NOT EXISTS idx_results_verdict ON results(verdict);
                CREATE INDEX IF NOT EXISTS idx_results_sha ON results(sha256);
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            """)

    def _import_legacy_json(self, legacy: Path) -> None:
        if not legacy.is_file():
            return
        with self._connect() as c:
            if c.execute("SELECT value FROM meta WHERE key = ?", (f"imported:{legacy}",)).fetchone():
                return
        try:
            records = json.loads(legacy.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for rec in records if isinstance(records, list) else []:
            self._insert(rec)
        with self._connect() as c:
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (f"imported:{legacy}", time.strftime("%Y-%m-%d %H:%M:%S")))

    def _insert(self, rec: Dict[str, Any]) -> None:
        with self._connect() as c:
            c.execute("INSERT OR IGNORE INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)", (
                rec.get("scan_id"), rec.get("target_path"), rec.get("timestamp"), rec.get("duration_seconds"),
                rec.get("model_version"), json.dumps(rec.get("summary", {})), time.time()))
            c.executemany("INSERT OR IGNORE INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
                (rec.get("scan_id"), i, r.get("file_path"), r.get("file_name"), r.get("file_size_bytes"), r.get("sha256"),
                 r.get("verdict"), r.get("malware_probability"), r.get("novelty_score"), int(bool(r.get("is_novel"))),
                 json.dumps(r.get("evidence_points", [])), r.get("scan_duration_ms"), r.get("model_version"),
                 r.get("warning_message"))
                for i, r in enumerate(rec.get("results", []))])

    def record_scan(self, report: "ScanReport") -> None:
        d = report.to_dict()
        self._insert({
            "scan_id": d["scan_id"], "target_path": d["target_path"], "timestamp": d["start_time"],
            "duration_seconds": d["duration_seconds"], "model_version": d["model_version"], "summary": d["summary"],
            "results": [dict(r, model_version=report.results[i].model_version) for i, r in enumerate(d["results"])],
        })

    def _results(self, c, scan_id: str) -> List[Dict[str, Any]]:
        rows = c.execute("SELECT file_path, file_name, file_size_bytes, sha256, verdict, malware_probability, "
                         "novelty_score, is_novel, evidence, scan_duration_ms, model_version, warning_message "
                         "FROM results WHERE scan_id = ? ORDER BY idx", (scan_id,)).fetchall()
        keys = ("file_path", "file_name", "file_size_bytes", "sha256", "verdict", "malware_probability",
                "novelty_score", "is_novel", "evidence_points", "scan_duration_ms", "model_version", "warning_message")
        out = []
        for row in rows:
            r = dict(zip(keys, row))
            r["is_novel"] = bool(r["is_novel"])
            r["evidence_points"] = json.loads(r["evidence_points"] or "[]")
            out.append(r)
        return out

    def load_history(self, limit: Optional[int] = None, include_results: bool = True) -> List[Dict[str, Any]]:
        """Oldest first (v0.1 order). `limit` keeps the most recent N scans."""
        with self._connect() as c:
            q = "SELECT scan_id, target_path, timestamp, duration_seconds, model_version, summary FROM scans ORDER BY created"
            scans = c.execute(q).fetchall()
            if limit:
                scans = scans[-limit:]
            out = []
            for sid, target, ts, dur, mv, summary in scans:
                rec = {"scan_id": sid, "target_path": target, "timestamp": ts, "duration_seconds": dur,
                       "model_version": mv, "summary": json.loads(summary)}
                if include_results:
                    rec["results"] = self._results(c, sid)
                out.append(rec)
            return out

    def search_results(self, verdicts: Optional[List[str]] = None, text: Optional[str] = None,
                       limit: int = 200) -> List[Dict[str, Any]]:
        """Detections across all scans, newest first (for the Detections view)."""
        sql = ("SELECT r.scan_id, s.timestamp, r.file_path, r.file_name, r.sha256, r.verdict, r.malware_probability "
               "FROM results r JOIN scans s USING (scan_id) WHERE 1=1")
        args: List[Any] = []
        if verdicts:
            sql += f" AND r.verdict IN ({','.join('?' * len(verdicts))})"
            args += verdicts
        if text:
            sql += " AND (r.file_path LIKE ? OR r.sha256 LIKE ?)"
            args += [f"%{text}%", f"{text.lower()}%"]
        sql += " ORDER BY s.created DESC, r.idx LIMIT ?"
        args.append(int(limit))
        keys = ("scan_id", "timestamp", "file_path", "file_name", "sha256", "verdict", "malware_probability")
        with self._connect() as c:
            return [dict(zip(keys, row)) for row in c.execute(sql, args).fetchall()]
