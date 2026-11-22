"""'Known Malicious' tier: local SHA-256 hash lists and YARA rules.

* Hash lists — plain-text files, one SHA-256 per line, optional "# label" after it:
      <rules_dir>/hashes/*.txt          known-bad hashes
      <rules_dir>/allowlist/*.txt       user-approved hashes (suppress hash and YARA matches)
* YARA rules — <rules_dir>/yara/**/*.yar|*.yara, compiled once into a cache keyed by the
  rule files' SHA-256, scanned with a per-file timeout.

No third-party rules or hash feeds are bundled (licensing). Everything is local and offline;
nothing is uploaded anywhere. Matches are reported with the rule or list name so the
verdict always says *what* matched.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def default_rules_dir() -> Path:
    base = os.environ.get("THREATWEAVER_RULES_DIR")
    if base:
        return Path(base)
    from threatweaver.core.paths import app_data_dir
    return app_data_dir() / "rules"


def _load_hash_files(directory: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not directory.is_dir():
        return out
    for f in sorted(directory.glob("*.txt")):
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split("#", 1)
            h = parts[0].strip()
            if SHA256_RE.match(h):
                label = parts[1].strip() if len(parts) > 1 and parts[1].strip() else f.stem
                out[h.lower()] = label
    return out


@dataclass
class KnownBadResult:
    match: Optional[str] = None                 # human-readable "what matched"
    yara_rules: List[str] = field(default_factory=list)
    hash_list: Optional[str] = None
    allowlisted: bool = False
    yara_error: Optional[str] = None


class KnownBadDetector:
    def __init__(self, rules_dir: Optional[str | Path] = None, yara_timeout_s: int = 10):
        self.rules_dir = Path(rules_dir) if rules_dir else default_rules_dir()
        self.yara_timeout_s = yara_timeout_s
        self.bad_hashes = _load_hash_files(self.rules_dir / "hashes")
        self.allow_hashes = _load_hash_files(self.rules_dir / "allowlist")
        self.rule_files = sorted(
            [p for ext in ("*.yar", "*.yara") for p in (self.rules_dir / "yara").rglob(ext)]
        ) if (self.rules_dir / "yara").is_dir() else []
        self.rules_digest = hashlib.sha256(
            b"".join(p.read_bytes() for p in self.rule_files)).hexdigest() if self.rule_files else None
        self._rules = None
        self.load_error: Optional[str] = None
        if self.rule_files:
            self._compile()

    def _compile(self) -> None:
        try:
            import yara
        except ImportError:
            self.load_error = "yara-python is not installed; YARA rules are inactive"
            return
        cache = self.rules_dir / ".compiled" / f"{self.rules_digest}.yarc"
        try:
            if cache.is_file():
                self._rules = yara.load(str(cache))
                return
            filepaths = {f"r{i}": str(p) for i, p in enumerate(self.rule_files)}
            self._rules = yara.compile(filepaths=filepaths)
            cache.parent.mkdir(parents=True, exist_ok=True)
            self._rules.save(str(cache))
        except Exception as e:  # noqa: BLE001 - a broken rule file must not stop scanning
            self._rules = None
            self.load_error = f"YARA rules failed to compile: {e}"

    @property
    def version(self) -> str:
        """Changes whenever rules or lists change (part of the scan-cache fingerprint)."""
        h = hashlib.sha256()
        h.update((self.rules_digest or "").encode())
        h.update("|".join(sorted(self.bad_hashes)).encode())
        h.update("|".join(sorted(self.allow_hashes)).encode())
        return h.hexdigest()[:16]

    @property
    def active(self) -> bool:
        return bool(self.bad_hashes or self._rules is not None)

    def check(self, sha256: str, path: Optional[str | Path] = None) -> KnownBadResult:
        sha = (sha256 or "").lower()
        if sha in self.allow_hashes:
            return KnownBadResult(allowlisted=True)
        res = KnownBadResult()
        if sha in self.bad_hashes:
            res.hash_list = self.bad_hashes[sha]
            res.match = f"hash list '{res.hash_list}'"
        if self._rules is not None and path is not None:
            try:
                matches = self._rules.match(str(path), timeout=self.yara_timeout_s)
                res.yara_rules = sorted({m.rule for m in matches})
            except Exception as e:  # noqa: BLE001 - includes yara.TimeoutError
                res.yara_error = f"{type(e).__name__}: {e}"
            if res.yara_rules and res.match is None:
                res.match = "YARA rule(s) " + ", ".join(res.yara_rules)
        return res
