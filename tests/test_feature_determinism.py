"""Feature vectors must be identical across processes (Python's hash() is salted per process)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = (
    "import json, sys; sys.path.insert(0, {src!r});"
    "from threatweaver.scanner.feature_extractor import FeatureExtractor;"
    "v = FeatureExtractor().extract_from_file({path!r}).feature_vector;"
    "print(json.dumps([round(float(x), 7) for x in v]))"
)


def _vector_in_subprocess(pe: Path, seed: str):
    env = dict(os.environ, PYTHONHASHSEED=seed)
    out = subprocess.run(
        [sys.executable, "-c", SCRIPT.format(src=str(REPO / "src"), path=str(pe))],
        capture_output=True, text=True, env=env, timeout=120, check=True,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("sample", ["benign_utility.exe", "suspicious_packed.exe"])
def test_feature_vector_identical_across_hash_seeds(sample):
    pe = REPO / "samples" / sample
    if not pe.is_file():
        pytest.skip("sample missing")
    vectors = [_vector_in_subprocess(pe, seed) for seed in ("0", "1", "12345")]
    assert vectors[0] == vectors[1] == vectors[2]


def test_real_windows_binary_import_buckets_stable():
    notepad = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "notepad.exe"
    if not notepad.is_file():
        pytest.skip("notepad.exe not available")
    a = _vector_in_subprocess(notepad, "0")
    b = _vector_in_subprocess(notepad, "987")
    assert any(x != 0 for x in a[112:160]), "notepad imports should populate import buckets"
    assert a == b


def test_stable_bucket_known_values():
    from threatweaver.scanner.feature_extractor import stable_bucket

    # CRC-32 is fixed by specification, so these values never change.
    assert stable_bucket("kernel32.dll", 24) == stable_bucket("kernel32.dll", 24)
    assert 0 <= stable_bucket("CreateRemoteThread", 1280) < 1280
    import zlib
    assert stable_bucket("abc", 24) == zlib.crc32(b"abc") % 24
