"""Dataset pipeline test on a tiny partition tree made from real EMBER2024 records."""

import json
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("thrember")

from threatweaver.data.ember_v3_dataset import build_dataset, load_split, parse_metadata_prefix, verify_outputs

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "data" / "ember2024" / "Dot_Net_test"


def _real_lines(n: int):
    files = sorted(SRC.glob("*.jsonl")) if SRC.is_dir() else []
    if not files:
        pytest.skip("EMBER2024 Dot_Net_test not present")
    out = []
    with open(files[0], "rb") as f:
        for line in f:
            out.append(line)
            if len(out) >= n:
                break
    return out


def _write(path: Path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(lines))


def test_metadata_prefix_parsing():
    line = _real_lines(1)[0]
    meta = parse_metadata_prefix(line)
    assert meta["label"] in (0, 1) and meta["file_type"] == "Dot_Net" and len(meta["sha256"]) == 64
    assert "histogram" not in meta


def test_build_dataset_end_to_end(tmp_path: Path):
    lines = _real_lines(60)
    train, test = lines[:40], lines[40:]
    # Spread train timestamps across two weeks of files and inject edge cases
    dup = train[0]
    unlabeled = json.loads(train[1])
    unlabeled["label"] = -1
    unlabeled["sha256"] = "f" * 64
    data = tmp_path / "ember2024"
    _write(data / "Dot_Net_train" / "2024-01-01_w1.jsonl", train[:20])
    _write(data / "Dot_Net_train" / "2024-01-08_w2.jsonl", train[20:] + [dup, (json.dumps(unlabeled) + "\n").encode()])
    _write(data / "Dot_Net_test" / "2024-09-22_t.jsonl", test)

    out = tmp_path / "ember_v3"
    m = build_dataset(data, out, file_types=["Dot_Net"], val_weeks=0, workers=2, batch_size=7, log=lambda *_: None)

    assert m["scan_stats"]["duplicates"] == 1
    assert m["scan_stats"]["unlabeled"] == 1
    total_train = m["splits"].get("train", {}).get("rows", 0) + m["splits"].get("val", {}).get("rows", 0)
    assert total_train == 40
    assert m["splits"]["test"]["rows"] == 20
    assert m["feature_dim"] == 2568 and m["feature_version"].startswith("ember-v3")

    X, y, meta = load_split(out, "test")
    assert X.shape == (20, 2568) and np.isfinite(X).all() and (X != 0).any(axis=1).all()
    assert len(y) == len(meta) == 20
    assert m["splits"]["test"]["vectorize_failures"] == 0
    assert set(meta["sha256"].to_list()).isdisjoint(set(load_split(out, "train")[2]["sha256"].to_list())
                                                  if "train" in m["splits"] else set())
    assert verify_outputs(out) == []

    # Tampering with an output is detected
    with open(out / "y_test.npy", "r+b") as f:
        f.seek(-1, 2)
        b = f.read(1)
        f.seek(-1, 2)
        f.write(bytes([b[0] ^ 1]))
    assert "y_test.npy" in verify_outputs(out)


def test_vectors_match_direct_extraction(tmp_path: Path):
    """Pipeline output rows equal what the scanner-side extractor produces for the same record."""
    from threatweaver.scanner.ember_v3 import EmberV3Extractor

    lines = _real_lines(12)
    data = tmp_path / "ember2024"
    _write(data / "Dot_Net_train" / "w1.jsonl", lines[:6])
    _write(data / "Dot_Net_test" / "t1.jsonl", lines[6:])
    out = tmp_path / "v3"
    build_dataset(data, out, file_types=["Dot_Net"], val_weeks=0, workers=1, log=lambda *_: None)
    X, _, meta = load_split(out, "test")
    ext = EmberV3Extractor()
    by_sha = {json.loads(l)["sha256"]: l for l in lines[6:]}
    for i, sha in enumerate(meta["sha256"].to_list()):
        assert np.array_equal(X[i], ext.vector_from_record(by_sha[sha].decode()))
