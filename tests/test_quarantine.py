"""Tests for safe reversible quarantine and recovery engine."""

import json
import os
from pathlib import Path
import pytest

from threatweaver.quarantine.manager import (
    QuarantineManager,
    CriticalSystemFileError,
    SymlinkReparsePointError,
    HashMismatchError,
    XOR_NEUTRALIZATION_KEY,
    ManifestIntegrityError,
    QuarantineError,
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

    manager = QuarantineManager(quarantine_dir=tmp_path / "vault", system_root=tmp_path / "Windows")
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


def test_folder_named_system32_outside_windows_is_quarantinable(tmp_path: Path):
    """Old substring matching let malware hide in any folder called 'system32' or 'boot'."""
    for name in ("system32", "boot", "bootstrap"):
        d = tmp_path / "Downloads" / name
        d.mkdir(parents=True)
        mal = create_minimal_pe(d / "explorer.exe")
        manager = QuarantineManager(quarantine_dir=tmp_path / f"vault_{name}", system_root=tmp_path / "Windows")
        entry = manager.quarantine_file(mal)
        assert not mal.exists() and Path(entry.quarantined_file).exists()


def test_real_system32_is_protected(tmp_path: Path):
    sysroot = os.environ.get("SystemRoot")
    notepad = Path(sysroot or "C:/Windows") / "System32" / "notepad.exe"
    if not notepad.is_file():
        pytest.skip("Windows System32 not available")
    manager = QuarantineManager(quarantine_dir=tmp_path / "vault")
    with pytest.raises(CriticalSystemFileError):
        manager.quarantine_file(notepad, dry_run=True)


def test_junction_in_parent_path_rejected(tmp_path: Path):
    """A directory junction must not be followed (the old check ran after resolve())."""
    _winapi = pytest.importorskip("_winapi")
    real = tmp_path / "real"
    real.mkdir()
    target = create_minimal_pe(real / "payload.exe")
    junction = tmp_path / "link"
    try:
        _winapi.CreateJunction(str(real), str(junction))
    except OSError as e:
        pytest.skip(f"cannot create junction: {e}")
    manager = QuarantineManager(quarantine_dir=tmp_path / "vault")
    with pytest.raises(SymlinkReparsePointError):
        manager.quarantine_file(junction / "payload.exe")
    assert target.exists()


def test_file_symlink_rejected(tmp_path: Path):
    real = create_minimal_pe(tmp_path / "real.exe")
    link = tmp_path / "link.exe"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted")
    manager = QuarantineManager(quarantine_dir=tmp_path / "vault")
    with pytest.raises(SymlinkReparsePointError):
        manager.quarantine_file(link)


def test_vault_files_cannot_be_quarantined(tmp_path: Path):
    manager = QuarantineManager(quarantine_dir=tmp_path / "vault")
    entry = manager.quarantine_file(create_minimal_pe(tmp_path / "a.exe"))
    with pytest.raises(CriticalSystemFileError):
        manager.quarantine_file(entry.quarantined_file)


def test_tampered_manifest_blocks_restore(tmp_path: Path):
    manager = QuarantineManager(quarantine_dir=tmp_path / "vault")
    entry = manager.quarantine_file(create_minimal_pe(tmp_path / "a.exe"))
    raw = json.loads(manager.manifest_path.read_text(encoding="utf-8"))
    raw[entry.quarantine_id]["original_path"] = str(tmp_path / "Startup" / "evil.exe")
    manager.manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ManifestIntegrityError):
        manager.restore_file(entry.quarantine_id)
    assert not (tmp_path / "Startup" / "evil.exe").exists()


def test_deleted_manifest_signature_detected(tmp_path: Path):
    manager = QuarantineManager(quarantine_dir=tmp_path / "vault")
    entry = manager.quarantine_file(create_minimal_pe(tmp_path / "a.exe"))
    from threatweaver.models import signing
    signing.signature_path(manager.manifest_path).unlink()
    with pytest.raises(ManifestIntegrityError):
        manager.restore_file(entry.quarantine_id)


def test_restore_refuses_data_file_outside_vault(tmp_path: Path):
    manager = QuarantineManager(quarantine_dir=tmp_path / "vault", sign_manifest=False)
    entry = manager.quarantine_file(create_minimal_pe(tmp_path / "a.exe"))
    raw = json.loads(manager.manifest_path.read_text(encoding="utf-8"))
    raw[entry.quarantine_id]["quarantined_file"] = str(tmp_path / "elsewhere.qf")
    manager.manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(QuarantineError):
        manager.restore_file(entry.quarantine_id)


def test_legacy_unsigned_vault_still_restores(tmp_path: Path):
    """Vaults written by v0.1 (no manifest signature) remain restorable."""
    legacy = QuarantineManager(quarantine_dir=tmp_path / "vault", sign_manifest=False)
    original = create_minimal_pe(tmp_path / "old.exe")
    data = original.read_bytes()
    entry = legacy.quarantine_file(original)
    upgraded = QuarantineManager(quarantine_dir=tmp_path / "vault")
    restored = upgraded.restore_file(entry.quarantine_id)
    assert restored.read_bytes() == data


def test_large_file_streams_with_bounded_memory(tmp_path: Path):
    import tracemalloc
    big = tmp_path / "big.exe"
    with open(big, "wb") as f:
        f.write(b"MZ")
        for _ in range(64):
            f.write(os.urandom(1024 * 1024))
    size = big.stat().st_size
    manager = QuarantineManager(quarantine_dir=tmp_path / "vault")
    tracemalloc.start()
    entry = manager.quarantine_file(big)
    restored = manager.restore_file(entry.quarantine_id)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert restored.stat().st_size == size
    assert peak < 16 * 1024 * 1024, f"peak traced memory {peak / 1e6:.1f} MB for a {size / 1e6:.0f} MB file"
