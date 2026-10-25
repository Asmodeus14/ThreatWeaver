"""Tests for Windows Authenticode & System Catalog Signature Verifier."""

import sys
from pathlib import Path
import pytest

from threatweaver.scanner.signature_verifier import WindowsSignatureVerifier, SignatureStatus
from tests.fixtures import create_minimal_pe


def test_signature_verifier_initialization():
    """Validates signature verifier instantiation and platform detection."""
    verifier = WindowsSignatureVerifier()
    if sys.platform == "win32":
        assert verifier.is_windows is True
        assert verifier.enabled is True
    else:
        assert verifier.enabled is False


def test_signature_verifier_disabled():
    """Validates behavior when explicitly disabled."""
    verifier = WindowsSignatureVerifier(enabled=False)
    assert verifier.enabled is False
    status = verifier.verify_file(sys.executable)
    assert status.is_trusted is False
    assert status.provider == "Disabled / Non-Windows"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Authenticode requires win32")
def test_verify_known_signed_executable():
    """Validates that python.exe or system binaries verify with a trusted signature."""
    verifier = WindowsSignatureVerifier()
    status = verifier.verify_file(sys.executable)
    # The active Python binary is typically signed by Python Software Foundation
    assert status.is_signed is True
    assert status.is_trusted is True
    assert status.provider in ("Authenticode Embedded", "Windows System Catalog")
    assert status.error_code == 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Authenticode requires win32")
def test_verify_system32_catalog_binary():
    """Validates catalog-signed Windows system executables."""
    verifier = WindowsSignatureVerifier()
    cmd_path = Path("C:/Windows/System32/cmd.exe")
    if cmd_path.is_file():
        status = verifier.verify_file(cmd_path)
        assert status.is_trusted is True
        assert "Windows" in status.provider or "Authenticode" in status.provider


def test_verify_unsigned_synthetic_pe(tmp_path: Path):
    """Validates that custom/synthetic PE files are identified as unsigned without error."""
    pe_file = create_minimal_pe(tmp_path / "unsigned.exe")
    verifier = WindowsSignatureVerifier()
    status = verifier.verify_file(pe_file)

    assert status.is_trusted is False


def test_verify_nonexistent_and_text_file(tmp_path: Path):
    """Validates that non-PE files safely degrade without crashing."""
    text_file = tmp_path / "plain.txt"
    text_file.write_text("Hello World", encoding="utf-8")

    verifier = WindowsSignatureVerifier()
    status = verifier.verify_file(text_file)
    assert status.is_trusted is False

    status_missing = verifier.verify_file(tmp_path / "missing.exe")
    assert status_missing.is_trusted is False
