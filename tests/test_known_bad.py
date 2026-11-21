"""Known-bad tier: hash lists, allowlist, YARA rules, cache invalidation and policy outcome."""

import shutil
from pathlib import Path

import pytest

from threatweaver.detectors.known_bad import KnownBadDetector
from tests.fixtures import create_minimal_pe

REPO = Path(__file__).resolve().parent.parent
SELFTEST_RULE = REPO / "rules" / "examples" / "threatweaver_selftest.yar"
MARKER = b"THREATWEAVER-YARA-SELFTEST-7f3c"


def _rules(tmp_path: Path, with_yara: bool = True) -> Path:
    d = tmp_path / "rules"
    (d / "hashes").mkdir(parents=True)
    (d / "allowlist").mkdir()
    if with_yara:
        (d / "yara").mkdir()
        shutil.copy(SELFTEST_RULE, d / "yara" / "selftest.yar")
    return d


def test_hash_list_match_and_label(tmp_path):
    d = _rules(tmp_path, with_yara=False)
    (d / "hashes" / "feed.txt").write_text("A" * 64 + "  # ExampleFamily\nnot-a-hash\n" + "b" * 64 + "\n")
    det = KnownBadDetector(d)
    assert det.check("a" * 64).match == "hash list 'ExampleFamily'"
    assert det.check("b" * 64).hash_list == "feed"           # label defaults to file name
    assert det.check("c" * 64).match is None


def test_allowlist_suppresses(tmp_path):
    d = _rules(tmp_path, with_yara=False)
    (d / "hashes" / "feed.txt").write_text("a" * 64 + "\n")
    (d / "allowlist" / "mine.txt").write_text("a" * 64 + "  # my build\n")
    r = KnownBadDetector(d).check("a" * 64)
    assert r.allowlisted and r.match is None


def test_yara_rule_match(tmp_path):
    pytest.importorskip("yara")
    d = _rules(tmp_path)
    f = tmp_path / "marked.bin"
    f.write_bytes(b"\x00" * 100 + MARKER + b"\x00" * 100)
    det = KnownBadDetector(d)
    assert det.load_error is None
    r = det.check("0" * 64, f)
    assert r.yara_rules == ["ThreatWeaver_SelfTest_Marker"] and "YARA" in r.match
    clean = tmp_path / "clean.bin"
    clean.write_bytes(b"\x00" * 300)
    assert det.check("1" * 64, clean).match is None
    assert list((d / ".compiled").glob("*.yarc")), "compiled rules are cached"


def test_broken_rule_does_not_crash(tmp_path):
    pytest.importorskip("yara")
    d = _rules(tmp_path, with_yara=False)
    (d / "yara").mkdir()
    (d / "yara" / "bad.yar").write_text("rule broken { condition: }")
    det = KnownBadDetector(d)
    assert det.load_error and not det.active


def test_version_changes_with_rules(tmp_path):
    d = _rules(tmp_path, with_yara=False)
    v1 = KnownBadDetector(d).version
    (d / "hashes" / "feed.txt").write_text("a" * 64 + "\n")
    assert KnownBadDetector(d).version != v1


def test_engine_reports_known_malicious_even_for_low_scores(tmp_path):
    """A YARA match overrides a low model score; the verdict names the rule."""
    pytest.importorskip("yara")
    pytest.importorskip("lightgbm")
    from threatweaver.scanner.inference import InferenceEngine, ScanVerdict

    bundle = REPO / "artifacts" / "models" / "lgbm-v3-dotnet"
    if not bundle.is_dir():
        pytest.skip("bundle not present")
    d = _rules(tmp_path)
    pe = create_minimal_pe(tmp_path / "tool.exe", raw_section_data=b"\x90" * 64 + MARKER + b"\x90" * 64)
    eng = InferenceEngine(bundle_path=bundle, rules_dir=d, cache_db_path=tmp_path / "c.db", enable_signature_verifier=False)
    try:
        r = eng.analyze_file(pe)
        assert r.verdict == ScanVerdict.KNOWN_MALICIOUS
        assert "ThreatWeaver_SelfTest_Marker" in r.evidence_points[0]
    finally:
        eng.close()
