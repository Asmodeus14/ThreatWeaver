"""Default detector selection (LightGBM bundle unless --legacy)."""
from pathlib import Path

import pytest

from threatweaver.app import server


def test_legacy_flag_forces_neural_model():
    assert server.resolve_detector_bundle("anything", legacy=True) is None


def test_explicit_bundle_wins(tmp_path):
    assert server.resolve_detector_bundle(tmp_path) == Path(tmp_path)


def test_default_is_shipped_win64_bundle_when_available():
    pytest.importorskip("lightgbm")
    pytest.importorskip("thrember")
    assert server.resolve_detector_bundle() == server.DEFAULT_BUNDLE
    assert server.DEFAULT_BUNDLE.name == "lgbm-v3-win64-dotnet"


def test_missing_default_bundle_falls_back(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "DEFAULT_BUNDLE", tmp_path / "absent")
    assert server.resolve_detector_bundle() is None


def test_shipped_default_bundle_loads_and_is_release_signed():
    pytest.importorskip("lightgbm")
    from threatweaver.models.bundle import LGBMBundle

    b = LGBMBundle.load(server.DEFAULT_BUNDLE)
    assert b.id == "lgbm-v3-win64-dotnet"
    assert 0.0 < b.tau_low < b.tau_high < 1.0
