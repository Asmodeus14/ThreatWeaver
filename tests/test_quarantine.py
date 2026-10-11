"""Tests for safe reversible quarantine and recovery engine."""

import os
from pathlib import Path
import pytest

from threatweaver.quarantine.manager import (
    QuarantineManager,
    CriticalSystemFileError,
    SymlinkReparsePointError,
    HashMismatchError,
    XOR_NEUTRALIZATION_KEY,
)
from tests.fixtures import create_minimal_pe


def test_quarantine_and_restore_cycle(tmp_path: Path):
    """Validates complete quarantine and restoration cycle with byte-level hash parity."""
    file_to_quarantine = create_minimal_pe(tmp_path / "target.exe")
    with open(file_to_quarantine, "rb") as f:
        original_bytes = f.read()

    q_dir = tmp_path / "quarantine_vault"
    manager = QuarantineManager(quarantine_dir=q_dir)

    # 1. Quarantine file
    entry = manager.quarantine_file(file_to_quarantine, reason="Test detection")
    assert not file_to_quarantine.exists()  # Original unlinked
    assert Path(entry.quarantined_file).exists()

    # 2. Check XOR neutralization (must NOT have valid MZ header in vault)
    with open(entry.quarantined_file, "rb") as f:
        stored_bytes = f.read()
    assert stored_bytes[:2] != b"MZ"
    assert bytes(b ^ XOR_NEUTRALIZATION_KEY for b in stored_bytes[:2]) == b"MZ"

    # 3. Restore file
    restored_path = manager.restore_file(entry.quarantine_id)
    assert restored_path.exists()
    assert not Path(entry.quarantined_file).exists()  # Vault cleaned

    # 4. Verify restored bytes match original exactly
    with open(restored_path, "rb") as f:
        restored_bytes = f.read()
    assert restored_bytes == original_bytes


def test_quarantine_dry_run(tmp_path: Path):
    """Validates dry-run mode without filesystem mutation."""
    sample = create_minimal_pe(tmp_path / "sample.exe")
    q_dir = tmp_path / "vault"
    manager = QuarantineManager(quarantine_dir=q_dir)

    entry = manager.quarantine_file(sample, dry_run=True)
    assert "[DRY RUN]" in entry.reason
    assert sample.exists()  # File preserved


def test_critical_system_file_rejection(tmp_path: Path):
    """Refuses to quarantine critical Windows operating system components."""
    fake_sys32 = tmp_path / "Windows" / "System32"
    fake_sys32.mkdir(parents=True)
    fake_kernel = fake_sys32 / "ntoskrnl.exe"
    fake_kernel.write_bytes(b"MZ" + b"\x00" * 300)

    manager = QuarantineManager(quarantine_dir=tmp_path / "vault")
    with pytest.raises(CriticalSystemFileError):
        manager.quarantine_file(fake_kernel)


def test_audit_log_generation(tmp_path: Path):
    """Verifies that quarantine actions write structured audit log entries."""
    sample = create_minimal_pe(tmp_path / "sample.exe")
    q_dir = tmp_path / "vault"
    manager = QuarantineManager(quarantine_dir=q_dir)

    entry = manager.quarantine_file(sample, reason="Audit test")
    manager.restore_file(entry.quarantine_id)

    assert manager.audit_log_path.exists()
    log_content = manager.audit_log_path.read_text(encoding="utf-8")
    assert "QUARANTINE_SUCCESS" in log_content
    assert "RESTORE_SUCCESS" in log_content
