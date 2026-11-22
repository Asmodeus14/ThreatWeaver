"""Shipped / loaded checkpoints must never be overwritten by runtime adaptation."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

import threatweaver.scanner.inference as inference_mod
from threatweaver.scanner.inference import InferenceEngine

REPO = Path(__file__).resolve().parent.parent
SHIPPED = REPO / "artifacts" / "checkpoints" / "threatweaver_128d.pt"
SAMPLE_PE = REPO / "samples" / "benign_utility.exe"

pytestmark = pytest.mark.skipif(not (SHIPPED.is_file() and SAMPLE_PE.is_file()), reason="shipped checkpoint/sample missing")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture
def engine(tmp_path, monkeypatch):
    src = tmp_path / "source.pt"
    shutil.copy(SHIPPED, src)
    shutil.copy(SHIPPED.with_name(SHIPPED.name + ".ed25519"), tmp_path / "source.pt.ed25519")
    monkeypatch.setattr(inference_mod, "LOCAL_MODELS_DIR", tmp_path / "local")
    eng = InferenceEngine(checkpoint_path=src, enable_hash_cache=False, enable_signature_verifier=False)
    return eng, src


def test_persisted_prototype_creates_new_version(engine):
    eng, src = engine
    before = sha(src)
    res = eng.register_prototype_from_sample(SAMPLE_PE, label=0, family_name="UnitTestBenign", persist=True)
    assert sha(src) == before, "source checkpoint was modified"
    new = Path(res["saved_checkpoint"])
    assert new.is_file() and new != src.resolve()
    assert new.with_name(new.name + ".ed25519").is_file()
    index = json.loads((new.parent / "index.json").read_text(encoding="utf-8"))
    assert index[-1]["parent"] == str(src.resolve())
    assert index[-1]["sha256"] == sha(new)


def test_default_registration_does_not_persist(engine):
    eng, src = engine
    res = eng.register_prototype_from_sample(SAMPLE_PE, label=0, family_name="Ephemeral")
    assert res["saved_checkpoint"] is None
    assert not (inference_mod.LOCAL_MODELS_DIR).exists()


def test_explicit_overwrite_of_source_refused(engine):
    eng, src = engine
    with pytest.raises(PermissionError):
        eng.save_state(src)


def test_overwrite_of_shipped_directory_refused(engine):
    eng, _ = engine
    with pytest.raises(PermissionError):
        eng.save_state(REPO / "artifacts" / "checkpoints" / "threatweaver_v1.pt")


def test_successive_saves_are_distinct_versions(engine):
    eng, _ = engine
    a = eng.save_state(reason="first")
    b = eng.save_state(reason="second")
    assert a != b and a.is_file() and b.is_file()
