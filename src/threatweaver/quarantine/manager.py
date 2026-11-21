"""Safe, reversible quarantine and restoration manager for ThreatWeaver.

Guarantees:
* Reparse points (symlinks, junctions) are rejected on the *unresolved* path and every
  parent directory, before anything is resolved or opened.
* Critical Windows locations are protected by exact canonical prefix (e.g.
  %SystemRoot%\\System32\\...), not substring matching — so a folder named "system32"
  inside Downloads can still be quarantined, and real OS files cannot.
* Files are streamed in chunks (bounded memory), XOR-masked with 0x5A so the stored
  copy cannot execute by accident (neutralization, NOT encryption), written to a temp
  file, hash-verified, then atomically renamed into the vault.
* The manifest is Ed25519-signed with the per-install key; restores refuse a manifest
  that was edited outside ThreatWeaver, a data file outside the vault, or a destination
  that fails the path policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import numpy as np

XOR_NEUTRALIZATION_KEY = 0x5A  # Byte XOR mask to prevent accidental execution/indexing
CHUNK_SIZE = 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# Directories under %SystemRoot% whose contents must never be quarantined.
PROTECTED_SYSTEM_SUBDIRS = ("System32", "SysWOW64", "WinSxS", "Boot", "servicing", "SystemApps")
# Individual files directly under %SystemRoot%.
PROTECTED_SYSTEM_ROOT_FILES = ("explorer.exe", "regedit.exe", "notepad.exe", "hh.exe", "splwow64.exe")

# Retained for backward compatibility with code that imported the old name.
CRITICAL_WINDOWS_PATHS: Set[str] = {
    "system32", "syswow64", "winsxs", "boot", "driverstore", "ntoskrnl.exe", "hal.dll",
    "explorer.exe", "csrss.exe", "services.exe", "wininit.exe", "smss.exe", "svchost.exe",
    "kernel32.dll", "ntdll.dll", "user32.dll",
}


class QuarantineError(Exception):
    """Base exception for quarantine operations."""


class CriticalSystemFileError(QuarantineError):
    """Raised when quarantine is attempted on a protected system file."""


class SymlinkReparsePointError(QuarantineError):
    """Raised when target file (or a parent directory) is a symlink or reparse point."""


class HashMismatchError(QuarantineError):
    """Raised when pre- and post-operation SHA-256 hashes differ."""


class ManifestIntegrityError(QuarantineError):
    """Raised when the vault manifest was modified outside ThreatWeaver."""


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


def _norm(p: Path) -> str:
    return os.path.normcase(os.path.normpath(str(p)))


def _is_under(child: Path, parent: Path) -> bool:
    c, p = _norm(child), _norm(parent)
    return c == p or c.startswith(p.rstrip("\\/") + os.sep)


def is_reparse_point(path: Path) -> bool:
    """True if path itself is a symlink, junction or other reparse point (does not follow it)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def _xor_stream(src, dst, hasher_plain) -> int:
    """Copies src -> dst applying the XOR mask; updates hasher_plain with the UNMASKED bytes."""
    total = 0
    while True:
        chunk = src.read(CHUNK_SIZE)
        if not chunk:
            return total
        arr = np.frombuffer(chunk, dtype=np.uint8)
        out = np.bitwise_xor(arr, XOR_NEUTRALIZATION_KEY).tobytes()
        dst.write(out)
        total += len(chunk)
        if hasher_plain is not None:
            hasher_plain.update(chunk)


class QuarantineManager:
    """Manages file isolation and restoration with strict safety guarantees."""

    def __init__(
        self,
        quarantine_dir: str | Path = "quarantine_store",
        system_root: Optional[str | Path] = None,
        sign_manifest: bool = True,
    ):
        self.quarantine_dir = Path(quarantine_dir).resolve()
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.quarantine_dir / "quarantine.manifest.json"
        self.audit_log_path = self.quarantine_dir / "audit.log"
        self._signed_marker = self.quarantine_dir / ".manifest-signed"
        root = system_root or os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        self.system_root: Optional[Path] = Path(root).resolve() if root else None
        self.sign_manifest = sign_manifest

    # ------------------------------------------------------------------ audit / manifest

    def _log_audit(self, action: str, details: Dict[str, Any]) -> None:
        record = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "action": action, "details": details}
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _verify_manifest(self) -> None:
        """Raises ManifestIntegrityError if a previously signed manifest no longer verifies."""
        if not self.sign_manifest or not self.manifest_path.is_file():
            return
        from threatweaver.models import signing
        if not signing.signature_path(self.manifest_path).is_file():
            if self._signed_marker.is_file():
                raise ManifestIntegrityError("Vault manifest signature is missing (manifest was replaced).")
            return  # legacy (pre-signing) vault: trusted once, signed on next save
        res = signing.verify_file(self.manifest_path)
        if not res.valid:
            raise ManifestIntegrityError(f"Vault manifest failed verification: {res.reason}")

    def _load_manifest(self, verify: bool = True) -> Dict[str, QuarantineEntry]:
        if not self.manifest_path.is_file():
            return {}
        if verify:
            self._verify_manifest()
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return {k: QuarantineEntry(**v) for k, v in raw.items()}
        except (OSError, ValueError, TypeError):
            return {}

    def _save_manifest(self, manifest: Dict[str, QuarantineEntry]) -> None:
        tmp = self.manifest_path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({k: asdict(v) for k, v in manifest.items()}, f, indent=2)
        os.replace(tmp, self.manifest_path)
        if self.sign_manifest:
            from threatweaver.models import signing
            signing.sign_file(self.manifest_path, role="local")
            self._signed_marker.write_text("1", encoding="utf-8")

    def _compute_hash(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        return h.hexdigest()

    # ------------------------------------------------------------------ policy checks

    def _protected_prefixes(self) -> List[Path]:
        if not self.system_root:
            return []
        return [self.system_root / d for d in PROTECTED_SYSTEM_SUBDIRS]

    def check_is_critical_system_file(self, target_path: Path) -> bool:
        """True if target lies inside a protected OS directory, is a protected file directly
        under %SystemRoot%, or is inside the quarantine vault itself."""
        p = Path(os.path.abspath(target_path))
        if _is_under(p, self.quarantine_dir):
            return True
        for prefix in self._protected_prefixes():
            if _is_under(p, prefix):
                return True
        if self.system_root and _norm(p.parent) == _norm(self.system_root):
            return p.name.lower() in PROTECTED_SYSTEM_ROOT_FILES
        return False

    def _reject_reparse_points(self, path: Path) -> None:
        """Checks the file and each parent directory on the unresolved absolute path."""
        for candidate in [path, *path.parents]:
            if is_reparse_point(candidate):
                raise SymlinkReparsePointError(
                    f"Refusing to operate through symlink or reparse point: {candidate}"
                )

    # ------------------------------------------------------------------ operations

    def quarantine_file(
        self,
        file_path: str | Path,
        reason: str = "Suspicious executable",
        dry_run: bool = False,
    ) -> QuarantineEntry:
        """Isolates a file reversibly with streaming XOR masking and hash verification."""
        path = Path(os.path.abspath(Path(file_path).expanduser()))

        # 1. Reparse-point protection BEFORE resolving anything
        self._reject_reparse_points(path)
        if not path.is_file():
            raise FileNotFoundError(f"Target file not found: {path}")

        # 2. Critical Windows protection on the canonical path
        if self.check_is_critical_system_file(path) or self.check_is_critical_system_file(path.resolve()):
            raise CriticalSystemFileError(f"Refusing to quarantine critical operating system component: {path}")

        orig_size = path.stat().st_size
        qid = str(uuid.uuid4())[:12]
        dest_path = self.quarantine_dir / f"{qid}.qf"

        if dry_run:
            orig_sha = self._compute_hash(path)
            self._log_audit("DRY_RUN_QUARANTINE", {"file": str(path), "sha256": orig_sha, "size": orig_size, "qid": qid})
            return QuarantineEntry(
                quarantine_id=qid, original_path=str(path), original_filename=path.name,
                file_size_bytes=orig_size, sha256=orig_sha,
                quarantined_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                quarantined_file=str(dest_path), reason=f"[DRY RUN] {reason}",
            )

        manifest = self._load_manifest()  # verify before mutating

        # 3. Stream original -> masked temp file, hashing the plaintext on the way
        part = dest_path.with_suffix(".qf.part")
        plain_hash = hashlib.sha256()
        with open(path, "rb") as f_in, open(part, "wb") as f_out:
            written = _xor_stream(f_in, f_out, plain_hash)
            f_out.flush()
            os.fsync(f_out.fileno())
        orig_sha = plain_hash.hexdigest()

        # 4. Verify the stored copy decodes back to the original bytes
        verify_hash = hashlib.sha256()
        with open(part, "rb") as f_chk:
            while chunk := f_chk.read(CHUNK_SIZE):
                verify_hash.update(np.bitwise_xor(np.frombuffer(chunk, dtype=np.uint8), XOR_NEUTRALIZATION_KEY).tobytes())
        if verify_hash.hexdigest() != orig_sha or written != orig_size:
            part.unlink(missing_ok=True)
            raise HashMismatchError("Integrity verification failed during neutralization.")
        os.replace(part, dest_path)

        # 5. Remove the original only after the vault copy is durable and verified
        try:
            path.unlink()
        except OSError as e:
            dest_path.unlink(missing_ok=True)
            raise QuarantineError(f"Failed to remove original file: {e}")

        entry = QuarantineEntry(
            quarantine_id=qid, original_path=str(path), original_filename=path.name,
            file_size_bytes=orig_size, sha256=orig_sha,
            quarantined_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            quarantined_file=str(dest_path), reason=reason,
        )
        manifest[qid] = entry
        self._save_manifest(manifest)
        self._log_audit("QUARANTINE_SUCCESS", {
            "qid": qid, "original_path": str(path), "sha256": orig_sha, "size": orig_size, "reason": reason,
        })
        return entry

    def restore_file(
        self,
        quarantine_id: str,
        restore_destination: Optional[str | Path] = None,
        overwrite: bool = False,
        dry_run: bool = False,
    ) -> Path:
        """Restores a quarantined file with manifest, location and hash verification."""
        manifest = self._load_manifest()  # raises ManifestIntegrityError if tampered
        if quarantine_id not in manifest:
            raise KeyError(f"Quarantine ID '{quarantine_id}' not found in manifest.")
        entry = manifest[quarantine_id]
        if entry.restored:
            raise QuarantineError(f"File '{quarantine_id}' has already been restored.")

        # The data file must be a direct child of this vault.
        qf_path = Path(entry.quarantined_file)
        if _norm(qf_path.parent) != _norm(self.quarantine_dir) or qf_path.suffix != ".qf":
            raise QuarantineError(f"Quarantined data file is outside the vault: {qf_path}")
        if not qf_path.is_file():
            raise FileNotFoundError(f"Quarantined data file missing: {qf_path}")

        from threatweaver.app.security import PathPolicyError, validate_user_path
        try:
            target = validate_user_path(str(restore_destination or entry.original_path), must_exist=False)
        except PathPolicyError as e:
            raise QuarantineError(f"Restore destination rejected: {e}")
        target = Path(os.path.abspath(target))
        self._reject_reparse_points(target.parent)
        if _is_under(target, self.quarantine_dir):
            raise QuarantineError("Restore destination may not be inside the quarantine vault.")
        if target.exists() and not overwrite:
            raise FileExistsError(f"Destination path already exists and overwrite=False: {target}")

        if dry_run:
            self._log_audit("DRY_RUN_RESTORE", {"qid": quarantine_id, "dest": str(target)})
            return target

        target.parent.mkdir(parents=True, exist_ok=True)
        part = target.with_name(target.name + ".tw-restore")
        plain_hash = hashlib.sha256()
        with open(qf_path, "rb") as f_in, open(part, "wb") as f_out:
            while chunk := f_in.read(CHUNK_SIZE):
                plain = np.bitwise_xor(np.frombuffer(chunk, dtype=np.uint8), XOR_NEUTRALIZATION_KEY).tobytes()
                plain_hash.update(plain)
                f_out.write(plain)
            f_out.flush()
            os.fsync(f_out.fileno())
        if plain_hash.hexdigest() != entry.sha256:
            part.unlink(missing_ok=True)
            raise HashMismatchError(f"Restoration hash mismatch: expected {entry.sha256}, got {plain_hash.hexdigest()}")
        os.replace(part, target)

        entry.restored = True
        entry.restored_at = time.strftime("%Y-%m-%d %H:%M:%S")
        manifest[quarantine_id] = entry
        self._save_manifest(manifest)
        qf_path.unlink(missing_ok=True)
        self._log_audit("RESTORE_SUCCESS", {"qid": quarantine_id, "restored_path": str(target), "sha256": entry.sha256})
        return target

    def list_quarantined_files(self) -> List[QuarantineEntry]:
        """Returns all manifest entries (listing works even if the manifest fails verification)."""
        return list(self._load_manifest(verify=False).values())

    def manifest_integrity(self) -> Dict[str, Any]:
        try:
            self._verify_manifest()
            return {"ok": True}
        except ManifestIntegrityError as e:
            return {"ok": False, "reason": str(e)}
