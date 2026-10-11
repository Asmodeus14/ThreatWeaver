"""Tests for static PE parsing engine."""

import math
from pathlib import Path
import pytest

from threatweaver.scanner.pe_parser import (
    StaticPEParser,
    compute_shannon_entropy,
    compute_byte_histogram,
    FileTooLargeError,
)
from tests.fixtures import create_minimal_pe


def test_entropy_computation():
    """Validates Shannon entropy properties."""
    # Zero bytes -> entropy 0
    assert compute_shannon_entropy(b"") == 0.0
    # All identical bytes -> entropy 0
    assert compute_shannon_entropy(b"A" * 1000) == 0.0
    # 256 distinct bytes uniformly distributed -> entropy exactly 8.0
    uniform_bytes = bytes(range(256)) * 4
    ent = compute_shannon_entropy(uniform_bytes)
    assert math.isclose(ent, 8.0, rel_tol=1e-3)


def test_byte_histogram():
    """Validates byte histogram dimensionality and sum."""
    data = b"Hello, World! 1234567890"
    hist = compute_byte_histogram(data, num_bins=64)
    assert len(hist) == 64
    assert math.isclose(sum(hist), 1.0, rel_tol=1e-3)


def test_parse_valid_pe64(tmp_path: Path):
    """Validates structural extraction from a minimal 64-bit PE."""
    pe_file = create_minimal_pe(tmp_path / "valid64.exe", is_64bit=True)
    parser = StaticPEParser()
    result = parser.parse(pe_file)

    assert result.is_valid_pe is True
    assert result.machine_type == 0x8664
    assert result.machine_name == "IMAGE_FILE_MACHINE_AMD64"
    assert result.number_of_sections == 1
    assert len(result.sections) == 1
    assert result.sections[0].name == ".text"
    assert result.sections[0].is_executable is True
    assert result.sections[0].is_writable is False
    assert len(result.sha256) == 64
    assert result.error_message is None


def test_parse_valid_pe32(tmp_path: Path):
    """Validates structural extraction from a minimal 32-bit PE."""
    pe_file = create_minimal_pe(tmp_path / "valid32.exe", is_64bit=False)
    parser = StaticPEParser()
    result = parser.parse(pe_file)

    assert result.is_valid_pe is True
    assert result.machine_type == 0x014C
    assert result.machine_name == "IMAGE_FILE_MACHINE_I386"
    assert result.number_of_sections == 1


def test_detect_wx_anomaly(tmp_path: Path):
    """Flags section with both write and execute permissions (W^X violation)."""
    pe_file = create_minimal_pe(
        tmp_path / "wx.exe", is_64bit=True, writable_and_executable=True
    )
    parser = StaticPEParser()
    result = parser.parse(pe_file)

    assert result.is_valid_pe is True
    assert any("W^X violation" in a for a in result.anomalies)


def test_non_pe_handling(tmp_path: Path):
    """Gracefully handles non-PE files (e.g. text or random data)."""
    non_pe = tmp_path / "document.txt"
    non_pe.write_text("This is an ordinary text document. " * 20, encoding="utf-8")

    parser = StaticPEParser()
    result = parser.parse(non_pe)

    assert result.is_valid_pe is False
    assert "Missing MZ magic" in (result.error_message or "")


def test_truncated_pe_handling(tmp_path: Path):
    """Gracefully handles truncated files starting with MZ."""
    bad_pe = tmp_path / "truncated.exe"
    bad_pe.write_bytes(b"MZ" + b"\x00" * 30)  # less than MIN_PE_SIZE

    parser = StaticPEParser()
    result = parser.parse(bad_pe)

    assert result.is_valid_pe is False
    assert "too small" in (result.error_message or "")


def test_corrupt_e_lfanew_handling(tmp_path: Path):
    """Gracefully handles invalid PE pointer offset."""
    bad_pe = tmp_path / "bad_offset.exe"
    data = bytearray(b"MZ" + b"\x00" * 500)
    # Set e_lfanew at 0x3C to point to 0xFFFFFF (out of bounds)
    data[0x3C:0x40] = b"\xFF\xFF\x00\x00"
    bad_pe.write_bytes(data)

    parser = StaticPEParser()
    result = parser.parse(bad_pe)

    assert result.is_valid_pe is False
    assert "Invalid e_lfanew" in (result.error_message or "")


def test_file_too_large_rejection(tmp_path: Path):
    """Rejects files larger than configured bound."""
    large_file = tmp_path / "large.exe"
    large_file.write_bytes(b"MZ" + b"\x00" * 1024)

    # Configure very small max size (512 bytes)
    parser = StaticPEParser(max_file_size=512)
    result = parser.parse(large_file)

    assert result.is_valid_pe is False
    assert "exceeds limit" in (result.error_message or "")
