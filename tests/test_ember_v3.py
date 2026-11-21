"""EMBER2024 v3 (thrember) feature parity, determinism and drift tests."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("thrember")

from threatweaver.scanner.ember_v3 import FEATURE_DIM, FEATURE_VERSION, EmberV3Extractor, record_metadata

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"
GOLDEN = Path(__file__).parent / "golden" / "ember_v3_vectors.json"
DATA = REPO / "data" / "ember2024"


@pytest.fixture(scope="module")
def ext():
    return EmberV3Extractor()


def test_dimension(ext):
    assert ext.dim == FEATURE_DIM == 2568


@pytest.mark.parametrize("name", ["benign_utility.exe", "suspicious_packed.exe"])
def test_training_inference_parity_via_json_raw_features(ext, name):
    """EMBER2024 stores raw features as JSON; vectorizing that JSON must equal live extraction."""
    raw = ext.raw_from_bytes((SAMPLES / name).read_bytes())
    live = ext.vector_from_raw(raw)
    from_json = ext.vector_from_record(json.dumps(raw))
    assert np.array_equal(live, from_json)


def test_real_windows_binary_parity(ext):
    notepad = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "notepad.exe"
    if not notepad.is_file():
        pytest.skip("notepad.exe not available")
    raw = ext.raw_from_bytes(notepad.read_bytes())
    v = ext.vector_from_raw(raw)
    assert np.isfinite(v).all() and (v != 0).sum() > 500
    assert np.array_equal(v, ext.vector_from_record(json.dumps(raw)))


def test_golden_vectors_detect_extractor_drift(ext):
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert golden["feature_version"] == FEATURE_VERSION
    for name, expected in golden["vectors"].items():
        v = ext.vector_from_file(SAMPLES / name)
        assert hashlib.sha256(v.tobytes()).hexdigest() == expected["sha256_of_float32_vector"], (
            f"{name}: thrember output changed — feature version drift; retrain or re-pin")


def test_deterministic_across_processes():
    script = (
        "import sys, hashlib; sys.path.insert(0, {src!r});"
        "from threatweaver.scanner.ember_v3 import EmberV3Extractor;"
        "print(hashlib.sha256(EmberV3Extractor().vector_from_file({p!r}).tobytes()).hexdigest())"
    ).format(src=str(REPO / "src"), p=str(SAMPLES / "suspicious_packed.exe"))
    digests = {
        subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=180,
                       env=dict(os.environ, PYTHONHASHSEED=seed), check=True).stdout.strip().splitlines()[-1]
        for seed in ("0", "4242")
    }
    assert len(digests) == 1


def test_real_dataset_record_vectorizes(ext):
    files = sorted((DATA / "Dot_Net_test").glob("*.jsonl")) if DATA.is_dir() else []
    if not files:
        pytest.skip("EMBER2024 data not present")
    with open(files[0], encoding="utf-8") as f:
        line = f.readline()
    v = ext.vector_from_record(line)
    assert v.shape == (FEATURE_DIM,) and np.isfinite(v).all()
    meta = record_metadata(json.loads(line))
    assert meta["label"] in (0, 1) and "sha256" in meta


def test_size_limit_enforced(tmp_path):
    big = tmp_path / "big.exe"
    big.write_bytes(b"MZ" + b"\x00" * 2048)
    with pytest.raises(ValueError):
        EmberV3Extractor(max_bytes=1024).vector_from_file(big)


def test_non_pe_bytes_do_not_crash(ext):
    v = ext.vector_from_bytes(b"this is not a portable executable" * 10)
    assert v.shape == (FEATURE_DIM,) and np.isfinite(v).all()
