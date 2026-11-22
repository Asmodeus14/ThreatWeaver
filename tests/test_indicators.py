"""Static indicators from thrember raw features (crafted raw dicts + a real packed sample)."""

from pathlib import Path

import pytest

from threatweaver.detectors.indicators import indicators_from_raw

REPO = Path(__file__).resolve().parent.parent


def raw(**kw):
    base = {"general": {"is_pe": 1}, "section": {"entry": ".text", "sections": [
        {"name": ".text", "size": 8192, "vsize": 8192, "entropy": 6.1, "props": ["MEM_EXECUTE", "MEM_READ"]}],
        "overlay": {"size": 0, "size_ratio": 0, "entropy": 0}},
        "imports": {"kernel32.dll": ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "ExitProcess"]},
        "authenticode": {"num_certs": 0}, "pefilewarnings": []}
    base.update(kw)
    return base


def ids(r):
    return {i.id for i in indicators_from_raw(r)}


def test_clean_baseline_has_no_indicators():
    assert ids(raw()) == set()


def test_non_pe_yields_nothing():
    assert indicators_from_raw({"general": {"is_pe": 0}}) == []


def test_injection_triad_requires_all_three():
    two = raw(imports={"k32": ["VirtualAllocEx", "WriteProcessMemory"]})
    three = raw(imports={"k32": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]})
    assert "api_process_injection" not in ids(two)
    assert "api_process_injection" in ids(three)


def test_packer_wx_entry_overlay():
    r = raw(section={"entry": "UPX1", "sections": [
        {"name": "UPX0", "size": 0, "vsize": 0x40000, "entropy": 0, "props": ["MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]},
        {"name": "UPX1", "size": 65536, "vsize": 65536, "entropy": 7.9, "props": ["MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]}],
        "overlay": {"size": 900000, "size_ratio": 0.6, "entropy": 7.95}})
    got = ids(r)
    assert {"packer_sections", "writable_executable_section", "empty_raw_large_virtual", "unusual_entry_section",
            "high_entropy_section", "encrypted_overlay"} <= got


def test_signature_anomalies_only_when_signed():
    assert "self_signed_certificate" not in ids(raw(authenticode={"num_certs": 0, "self_signed": 1}))
    assert "self_signed_certificate" in ids(raw(authenticode={"num_certs": 1, "self_signed": 1}))


def test_timestamps_are_not_indicators():
    """Reproducible builds make 'future' timestamps common on clean Windows files."""
    assert ids(raw(header={"coff": {"timestamp": 4_000_000_000}})) == set()


def test_real_packed_sample():
    pytest.importorskip("thrember")
    from threatweaver.scanner.ember_v3 import get_extractor
    r = get_extractor().raw_from_bytes((REPO / "samples" / "suspicious_packed.exe").read_bytes())
    assert {"packer_sections", "writable_executable_section", "unusual_entry_section"} <= ids(r)
