"""Scan-result cache for ThreatWeaver (Tier 0).

Entries are keyed by (content SHA-256, engine fingerprint):

* content SHA-256 — computed from the file's bytes on every scan, so replacing a file and
  restoring its timestamp (``SetFileTime``) cannot produce a stale "benign" hit. The v0.1
  cache was keyed on path + mtime + size, which was spoofable.
* engine fingerprint — identifies the exact model checkpoint, novelty threshold, prototype
  set, decision threshold and verdict-policy version. Any change to these produces a
  different fingerprint, so verdicts never outlive the model that produced them.

In-memory LRU in front of SQLite (WAL).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from threatweaver.scanner.inference import ScanResult

DEFAULT_DB_NAME = "scan_cache.db"  # under threatweaver.core.paths.cache_dir()
MAX_MEMORY_CACHE_ENTRIES = 10000
NON_CACHEABLE_VERDICTS = ("Unsupported Format", "Analysis Error")


class CleanHashCache:
    """Thread-safe persistent scan-result cache keyed by content hash and engine fingerprint."""

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        max_mem_entries: int = MAX_MEMORY_CACHE_ENTRIES,
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.max_mem_entries = max_mem_entries
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()
        self._mem_cache: "OrderedDict[Tuple[str, str], ScanResult]" = OrderedDict()
        self._conn: Optional[sqlite3.Connection] = None

        if not self.enabled:
            return

        if db_path is None:
            from threatweaver.core.paths import cache_dir
            self.db_path = str(cache_dir() / DEFAULT_DB_NAME)
        else:
            p = Path(db_path)
            if str(p) != ":memory:":
                p.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(p)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10.0)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode = WAL;")
            cur.execute("PRAGMA synchronous = NORMAL;")
            # v0.1 table was keyed on path+mtime (spoofable) and had no model version: discard it.
            cur.execute("DROP TABLE IF EXISTS clean_cache;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_cache_v2 (
                    sha256 TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    malware_prob REAL NOT NULL,
                    novelty_score REAL NOT NULL,
                    is_novel INTEGER NOT NULL,
                    evidence TEXT NOT NULL,
                    nearest_cluster TEXT,
                    source TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (sha256, fingerprint)
                );
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_sha256 ON scan_cache_v2(sha256);")
            self._conn.commit()

    def _row_to_result(self, row, file_path: Optional[str]) -> "ScanResult":
        from threatweaver.scanner.inference import ScanResult, ScanVerdict

        (sha256, db_path, size, verd, prob, nov, is_nov, ev_json, nearest, source, model_version) = row
        path = file_path or db_path
        return ScanResult(
            file_path=str(path),
            file_name=Path(path).name,
            file_size_bytes=size,
            sha256=sha256,
            verdict=ScanVerdict(verd),
            malware_probability=prob,
            novelty_score=nov,
            is_novel=bool(is_nov),
            evidence_points=json.loads(ev_json) if ev_json else [],
            scan_duration_ms=0.0,
            model_version=f"Cached ({source}; {model_version})",
            raw_indicators=[],
            nearest_known_cluster=nearest,
            warning_message=None,
        )

    _SELECT = ("SELECT sha256, file_path, file_size, verdict, malware_prob, novelty_score, is_novel, "
               "evidence, nearest_cluster, source, model_version FROM scan_cache_v2 ")

    def lookup(self, sha256: str, fingerprint: str, file_path: Optional[str | Path] = None) -> Optional["ScanResult"]:
        """Returns the cached result for exactly these bytes under exactly this engine, else None."""
        if not self.enabled or not sha256 or not fingerprint:
            return None
        key = (sha256.lower(), fingerprint)
        with self._lock:
            cached = self._mem_cache.get(key)
            if cached is not None:
                self._mem_cache.move_to_end(key)
                self.hits += 1
                if file_path is not None:
                    from dataclasses import replace
                    cached = replace(cached, file_path=str(file_path), file_name=Path(file_path).name)
                return cached
            try:
                row = self._conn.execute(self._SELECT + "WHERE sha256 = ? AND fingerprint = ?;", key).fetchone()
            except sqlite3.Error:
                row = None
            if row is None:
                self.misses += 1
                return None
            res = self._row_to_result(row, str(file_path) if file_path is not None else None)
            self._mem_cache[key] = res
            if len(self._mem_cache) > self.max_mem_entries:
                self._mem_cache.popitem(last=False)
            self.hits += 1
            return res

    def lookup_hash(self, sha256: str, fingerprint: Optional[str] = None) -> Optional["ScanResult"]:
        """Looks up by content hash; restricted to one engine fingerprint when given."""
        if not self.enabled or not sha256:
            return None
        if fingerprint:
            return self.lookup(sha256, fingerprint)
        try:
            with self._lock:
                row = self._conn.execute(
                    self._SELECT + "WHERE sha256 = ? ORDER BY updated_at DESC LIMIT 1;", (sha256.lower(),)
                ).fetchone()
        except sqlite3.Error:
            return None
        return self._row_to_result(row, None) if row else None

    def record_scan_result(self, result: "ScanResult", fingerprint: str, source: str = "Triage") -> None:
        """Stores a result for (result.sha256, fingerprint). Errors / unsupported files are never cached."""
        if not self.enabled or not result.sha256 or not fingerprint:
            return
        verdict_val = result.verdict.value if hasattr(result.verdict, "value") else str(result.verdict)
        if verdict_val in NON_CACHEABLE_VERDICTS:
            return
        key = (result.sha256.lower(), fingerprint)
        from dataclasses import replace
        cached_view = replace(
            result,
            scan_duration_ms=0.0,
            model_version=f"Cached ({source}; {result.model_version})",
        )
        with self._lock:
            self._mem_cache[key] = cached_view
            if len(self._mem_cache) > self.max_mem_entries:
                self._mem_cache.popitem(last=False)
            try:
                self._conn.execute(
                    """
                    INSERT INTO scan_cache_v2 (sha256, fingerprint, file_path, file_size, verdict, malware_prob,
                        novelty_score, is_novel, evidence, nearest_cluster, source, model_version, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sha256, fingerprint) DO UPDATE SET
                        file_path=excluded.file_path, file_size=excluded.file_size, verdict=excluded.verdict,
                        malware_prob=excluded.malware_prob, novelty_score=excluded.novelty_score,
                        is_novel=excluded.is_novel, evidence=excluded.evidence,
                        nearest_cluster=excluded.nearest_cluster, source=excluded.source,
                        model_version=excluded.model_version, updated_at=excluded.updated_at;
                    """,
                    (
                        key[0], fingerprint, str(Path(result.file_path).resolve()), result.file_size_bytes,
                        verdict_val, float(result.malware_probability), float(result.novelty_score),
                        1 if result.is_novel else 0, json.dumps(result.evidence_points),
                        result.nearest_known_cluster, source, str(result.model_version), time.time(),
                    ),
                )
                self._conn.commit()
            except sqlite3.Error:
                pass

    def remove(self, sha256: str) -> bool:
        """Removes every cached result for this content hash (all engine fingerprints)."""
        if not self.enabled:
            return False
        sha = sha256.lower()
        with self._lock:
            for k in [k for k in self._mem_cache if k[0] == sha]:
                del self._mem_cache[k]
            try:
                cur = self._conn.execute("DELETE FROM scan_cache_v2 WHERE sha256 = ?;", (sha,))
                self._conn.commit()
                return cur.rowcount > 0
            except sqlite3.Error:
                return False

    def invalidate(self, sha256: str) -> bool:
        return self.remove(sha256)

    def clear(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._mem_cache.clear()
            self.hits = 0
            self.misses = 0
            try:
                self._conn.execute("DELETE FROM scan_cache_v2;")
                self._conn.commit()
            except sqlite3.Error:
                pass

    def count(self) -> int:
        if not self.enabled:
            return 0
        try:
            with self._lock:
                row = self._conn.execute("SELECT COUNT(*) FROM scan_cache_v2;").fetchone()
            return row[0] if row else 0
        except sqlite3.Error:
            return 0

    def close(self) -> None:
        if self._conn is None:
            return
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
