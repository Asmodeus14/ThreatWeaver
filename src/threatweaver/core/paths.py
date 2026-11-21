"""Where ThreatWeaver reads resources and writes state.

* Writable, per-user state lives under the app-data directory (never the current working
  directory, which may be read-only, shared, or the user's Downloads folder):
      THREATWEAVER_HOME  or  %LOCALAPPDATA%\\ThreatWeaver  or  ~/.threatweaver
* Read-only shipped resources (checkpoints, model bundles, benchmark artifacts) are resolved
  from the install root: the repository root in development, ``sys._MEIPASS`` when frozen.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Dict, Optional


def app_data_dir() -> Path:
    override = os.environ.get("THREATWEAVER_HOME")
    if override:
        base = Path(override)
    elif os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"]) / "ThreatWeaver"
    else:
        base = Path.home() / ".threatweaver"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _sub(name: str) -> Path:
    p = app_data_dir() / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def vault_dir() -> Path:
    return _sub("quarantine")


def cache_dir() -> Path:
    return _sub("cache")


def history_db_path() -> Path:
    return _sub("history") / "history.db"


def local_models_dir() -> Path:
    return _sub("models") / "local"


def resource_root() -> Path:
    frozen = getattr(sys, "_MEIPASS", None)
    if frozen:
        return Path(frozen)
    return Path(__file__).resolve().parents[3]  # src/threatweaver/core/paths.py -> repo root


def resource_path(relative: str) -> Path:
    return resource_root() / relative


# ------------------------------------------------------------------ one-time migration

def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def migrate_legacy_vault(legacy: Optional[Path] = None, target: Optional[Path] = None) -> Dict[str, object]:
    """Copies a v0.1 CWD-relative ``quarantine_store`` into the app-data vault once.

    Copy-then-verify (SHA-256 of every file); the legacy folder is left in place with a
    MIGRATED.txt marker so nothing is ever lost. Skipped if the target already has a manifest.
    """
    legacy = legacy or (resource_root() / "quarantine_store")
    target = target or vault_dir()
    if not (legacy / "quarantine.manifest.json").is_file():
        return {"migrated": False, "reason": "no legacy vault"}
    if (legacy / "MIGRATED.txt").is_file() or (target / "quarantine.manifest.json").is_file():
        return {"migrated": False, "reason": "already migrated or target in use"}
    copied = []
    for f in sorted(legacy.iterdir()):
        if f.is_file():
            dest = target / f.name
            shutil.copy2(f, dest)
            if _sha256(f) != _sha256(dest):
                raise IOError(f"Vault migration verification failed for {f.name}")
            copied.append(f.name)
    # Rewrite data-file locations to the new vault (manifest is re-signed on next save by the manager)
    manifest_p = target / "quarantine.manifest.json"
    data = json.loads(manifest_p.read_text(encoding="utf-8"))
    for entry in data.values():
        entry["quarantined_file"] = str(target / Path(entry["quarantined_file"]).name)
    manifest_p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    for stale in ("quarantine.manifest.json.ed25519", ".manifest-signed"):
        (target / stale).unlink(missing_ok=True)
    (legacy / "MIGRATED.txt").write_text(
        f"Migrated to {target} on {time.strftime('%Y-%m-%d %H:%M:%S')}. Files: {', '.join(copied)}\n", encoding="utf-8")
    return {"migrated": True, "files": copied, "target": str(target)}
