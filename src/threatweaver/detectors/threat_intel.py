"""Opt-in hash reputation lookup (abuse.ch MalwareBazaar).

Privacy and safety rules:
* OFF by default. Nothing leaves the machine until the user enables it and supplies an API key.
* Only the SHA-256 of a scanned PE file is sent — never the file, its name or its path.
* Results are cached locally for 7 days; network failures never block or change a scan
  except to add an evidence line saying the lookup failed.
* A listing supplements local detection (Known Malicious, naming the reported signature);
  absence from the list is NOT evidence of safety and is reported as "not listed".
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

API_URL = "https://mb-api.abuse.ch/api/v1/"
CACHE_TTL_S = 7 * 86400
KEY_FILE = "malwarebazaar_api_key.bin"


@dataclass
class IntelResult:
    status: str                       # "listed" | "not_listed" | "error" | "disabled"
    source: str = "MalwareBazaar"
    signature: Optional[str] = None
    tags: Optional[list] = None
    first_seen: Optional[str] = None
    detail: Optional[str] = None
    cached: bool = False


def _paths():
    from threatweaver.core.paths import app_data_dir
    cfg = app_data_dir() / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    return cfg / "threat_intel.json", app_data_dir() / "cache" / "intel.db"


def load_config() -> dict:
    cfg_path, _ = _paths()
    try:
        return json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"enabled": False}


def save_config(enabled: bool, api_key: Optional[str] = None) -> dict:
    from threatweaver.models import signing

    cfg_path, _ = _paths()
    if api_key:
        signing._store_private(api_key.strip().encode("utf-8"), signing.key_dir() / KEY_FILE)
    has_key = (signing.key_dir() / KEY_FILE).is_file()
    cfg = {"enabled": bool(enabled and has_key), "has_api_key": has_key}
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    return cfg


def _api_key() -> Optional[str]:
    from threatweaver.models import signing
    p = signing.key_dir() / KEY_FILE
    try:
        return signing._load_private(p).decode("utf-8") if p.is_file() else None
    except (OSError, ValueError):
        return None


class MalwareBazaarLookup:
    def __init__(self, timeout_s: float = 5.0, opener=None):
        self.timeout_s = timeout_s
        self._open = opener or urllib.request.urlopen
        _, db = _paths()
        db.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(db, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS intel (sha256 TEXT PRIMARY KEY, result TEXT, ts REAL)")
        self._db.commit()

    @property
    def enabled(self) -> bool:
        return bool(load_config().get("enabled")) and _api_key() is not None

    def lookup(self, sha256: str) -> IntelResult:
        if not self.enabled:
            return IntelResult("disabled")
        sha = (sha256 or "").lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            return IntelResult("error", detail="invalid hash")
        with self._lock:
            row = self._db.execute("SELECT result, ts FROM intel WHERE sha256 = ?", (sha,)).fetchone()
        if row and time.time() - row[1] < CACHE_TTL_S:
            return IntelResult(**{**json.loads(row[0]), "cached": True})
        try:
            data = urllib.parse.urlencode({"query": "get_info", "hash": sha}).encode()
            req = urllib.request.Request(API_URL, data=data, method="POST",
                                         headers={"Auth-Key": _api_key() or "", "User-Agent": "ThreatWeaver/0.2"})
            with self._open(req, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001 - lookup failures are evidence, never fatal
            return IntelResult("error", detail=f"{type(e).__name__}: {e}")
        qs = body.get("query_status")
        if qs == "ok" and body.get("data"):
            d = body["data"][0]
            res = IntelResult("listed", signature=d.get("signature"), tags=d.get("tags"), first_seen=d.get("first_seen"))
        elif qs in ("hash_not_found", "no_results"):
            res = IntelResult("not_listed")
        else:
            return IntelResult("error", detail=f"query_status={qs}")
        with self._lock:
            payload = {k: v for k, v in res.__dict__.items() if k != "cached"}
            self._db.execute("INSERT OR REPLACE INTO intel VALUES (?, ?, ?)", (sha, json.dumps(payload), time.time()))
            self._db.commit()
        return res
