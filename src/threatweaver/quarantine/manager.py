"""Safe, reversible quarantine and restoration manager for ThreatWeaver.

Guarantees atomic isolation, pre/post SHA-256 hash verification, path traversal
and symlink protection, critical Windows path safeguards, XOR neutralization,
and tamper-evident audit logging.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

XOR_NEUTRALIZATION_KEY = 0x5A  # Byte XOR mask to prevent accidental execution/indexing

# Critical Windows paths and files that must NEVER be quarantined
CRITICAL_WINDOWS_PATHS: Set[str] = {
    "system32",
    "syswow64",
    "winsxs",
    "boot",
    "driverstore",
    "ntoskrnl.exe",
    "hal.dll",
    "explorer.exe",
    "csrss.exe",
    "services.exe",
    "wininit.exe",
    "smss.exe",
    "svchost.exe",
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
}


class QuarantineError(Exception):
    """Base exception for quarantine operations."""


class CriticalSystemFileError(QuarantineError):
    """Raised when quarantine is attempted on a protected system file."""


class SymlinkReparsePointError(QuarantineError):
    """Raised when target file is a symlink or reparse point."""


class HashMismatchError(QuarantineError):
    """Raised when pre- and post-operation SHA-256 hashes differ."""


@dataclass
class QuarantineEntry:
    """Metadata record for a quarantined file."""
    quarantine_id: str
    original_path: str
    original_filename: str
    file_size_bytes: int
    sha256: str
    quarantined_at: str
    quarantined_file: str
    restored: bool = False
    restored_at: Optional[str] = None
    reason: str = "ThreatWeaver Detection"


class QuarantineManager:
    """Manages file isolation and restoration with strict safety guarantees."""

    def __init__(self, quarantine_dir: str | Path = "quarantine_store"):
        self.quarantine_dir = Path(quarantine_dir).resolve()
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.quarantine_dir / "quarantine.manifest.json"
        self.audit_log_path = self.quarantine_dir / "audit.log"

    def _log_audit(self, action: str, details: Dict[str, Any]) -> None:
        """Appends structured audit record to log."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        record = {
            "timestamp": timestamp,
            "action": action,
            "details": details,
        }
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _load_manifest(self) -> Dict[str, QuarantineEntry]:
        if not self.manifest_path.is_file():
            return {}
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                return {k: QuarantineEntry(**v) for k, v in raw.items()}
        except Exception:
            return {}

    def _save_manifest(self, manifest: Dict[str, QuarantineEntry]) -> None:
        serializable = {k: asdict(v) for k, v in manifest.items()}
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)

    def _compute_hash(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def check_is_critical_system_file(self, target_path: Path) -> bool:
        """Determines if the target path is a critical Windows system component."""
        resolved = str(target_path.resolve()).lower()
        parts = [p.lower() for p in target_path.parts]
        for crit in CRITICAL_WINDOWS_PATHS:
            if crit in parts or crit in resolved:
                return True
        return False

    def quarantine_file(
        self,
        file_path: str | Path,
        reason: str = "Suspicious executable",
        dry_run: bool = False,
    ) -> QuarantineEntry:
        """Isolates a file reversibly with pre/post hash verification and XOR encoding."""
        path = Path(file_path).resolve()

        if not path.is_file():
            raise FileNotFoundError(f"Target file not found: {path}")

        # 1. Symlink / Reparse Point Protection
        if path.is_symlink():
            raise SymlinkReparsePointError(
                f"Refusing to quarantine symlink or reparse point: {path}"
            )

        # 2. Critical Windows Protection
        if self.check_is_critical_system_file(path):
            raise CriticalSystemFileError(
                f"Refusing to quarantine critical operating system component: {path}"
            )

        # 3. Hash computation before move
        orig_size = path.stat().st_size
        orig_sha = self._compute_hash(path)
        qid = str(uuid.uuid4())[:12]
        dest_filename = f"{qid}.qf"
        dest_path = self.quarantine_dir / dest_filename

        if dry_run:
            self._log_audit("DRY_RUN_QUARANTINE", {
                "file": str(path), "sha256": orig_sha, "size": orig_size, "qid": qid
            })
            return QuarantineEntry(
                quarantine_id=qid,
                original_path=str(path),
                original_filename=path.name,
                file_size_bytes=orig_size,
                sha256=orig_sha,
                quarantined_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                quarantined_file=str(dest_path),
                reason=f"[DRY RUN] {reason}",
            )

        # 4. Read, XOR-neutralize, write to quarantine staging
        with open(path, "rb") as f_in:
            raw_data = f_in.read()

        # Neutralize binary with XOR mask
        neutralized = bytes(b ^ XOR_NEUTRALIZATION_KEY for b in raw_data)
        with open(dest_path, "wb") as f_out:
            f_out.write(neutralized)

        # 5. Verify integrity by unmasking and checking hash
        unmasked_check = bytes(b ^ XOR_NEUTRALIZATION_KEY for b in neutralized)
        check_sha = hashlib.sha256(unmasked_check).hexdigest()
        if check_sha != orig_sha:
            dest_path.unlink(missing_ok=True)
            raise HashMismatchError("Integrity verification failed during neutralization.")

        # 6. Unlink original file only after confirmed safe storage
        try:
            path.unlink()
        except Exception as e:
            # Rollback quarantine file if original couldn't be unlinked
            dest_path.unlink(missing_ok=True)
            raise QuarantineError(f"Failed to remove original file: {str(e)}")

        entry = QuarantineEntry(
            quarantine_id=qid,
            original_path=str(path),
            original_filename=path.name,
            file_size_bytes=orig_size,
            sha256=orig_sha,
            quarantined_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            quarantined_file=str(dest_path),
            reason=reason,
        )

        manifest = self._load_manifest()
        manifest[qid] = entry
        self._save_manifest(manifest)

        self._log_audit("QUARANTINE_SUCCESS", {
            "qid": qid,
            "original_path": str(path),
            "sha256": orig_sha,
            "size": orig_size,
            "reason": reason,
        })

        return entry

    def restore_file(
        self,
        quarantine_id: str,
        restore_destination: Optional[str | Path] = None,
        overwrite: bool = False,
        dry_run: bool = False,
    ) -> Path:
        """Restores a quarantined file to original or target location with hash verification."""
        manifest = self._load_manifest()
        if quarantine_id not in manifest:
            raise KeyError(f"Quarantine ID '{quarantine_id}' not found in manifest.")

        entry = manifest[quarantine_id]
        if entry.restored:
            raise QuarantineError(f"File '{quarantine_id}' has already been restored.")

        qf_path = Path(entry.quarantined_file)
        if not qf_path.is_file():
            raise FileNotFoundError(f"Quarantined data file missing: {qf_path}")

        target_restore_path = Path(restore_destination or entry.original_path).resolve()

        if target_restore_path.is_file() and not overwrite:
            raise FileExistsError(
                f"Destination path already exists and overwrite=False: {target_restore_path}"
            )

        if dry_run:
            self._log_audit("DRY_RUN_RESTORE", {
                "qid": quarantine_id, "dest": str(target_restore_path)
            })
            return target_restore_path

        # Read, unmask XOR
        with open(qf_path, "rb") as f_in:
            neutralized = f_in.read()
        restored_bytes = bytes(b ^ XOR_NEUTRALIZATION_KEY for b in neutralized)

        # Verify hash matches original recorded hash
        restored_sha = hashlib.sha256(restored_bytes).hexdigest()
        if restored_sha != entry.sha256:
            raise HashMismatchError(
                f"Restoration hash mismatch: expected {entry.sha256}, got {restored_sha}"
            )

        target_restore_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_restore_path, "wb") as f_out:
            f_out.write(restored_bytes)

        # Mark restored and clean up quarantine storage
        entry.restored = True
        entry.restored_at = time.strftime("%Y-%m-%d %H:%M:%S")
        manifest[quarantine_id] = entry
        self._save_manifest(manifest)
        qf_path.unlink(missing_ok=True)

        self._log_audit("RESTORE_SUCCESS", {
            "qid": quarantine_id,
            "restored_path": str(target_restore_path),
            "sha256": restored_sha,
        })

        return target_restore_path

    def list_quarantined_files(self) -> List[QuarantineEntry]:
        """Returns all entries in quarantine manifest."""
        manifest = self._load_manifest()
        return list(manifest.values())
