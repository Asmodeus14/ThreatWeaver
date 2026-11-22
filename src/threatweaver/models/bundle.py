"""Signed LightGBM model bundles (artifacts/models/<id>/).

A bundle is: model.txt (LightGBM text format — no pickle), bundle.json (feature version,
calibration, thresholds, dataset manifest hash) and eval.json, each with an Ed25519
signature. Loading is fail-closed: missing/invalid signatures, a model file whose hash
differs from bundle.json, or a feature-version mismatch all raise.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import numpy as np

from threatweaver.models import signing


class BundleError(ValueError):
    pass


@dataclass
class LGBMBundle:
    path: Path
    meta: Dict[str, Any]
    booster: Any

    @property
    def id(self) -> str:
        return self.meta["id"]

    @property
    def tau_high(self) -> float:
        return float(self.meta["thresholds"]["tau_high_fpr_0.1pct"])

    @property
    def tau_low(self) -> float:
        return float(self.meta["thresholds"]["tau_low_fpr_1pct"])

    @classmethod
    def load(cls, path: str | Path, allow_unsigned: bool = False) -> "LGBMBundle":
        import lightgbm as lgb
        from threatweaver.scanner.ember_v3 import FEATURE_VERSION

        path = Path(path)
        for name in ("bundle.json", "model.txt"):
            f = path / name
            if not f.is_file():
                raise BundleError(f"Bundle file missing: {f}")
            res = signing.verify_file(f)
            if not res.valid and not signing.unsigned_allowed(allow_unsigned):
                raise BundleError(f"Bundle integrity verification failed for {f}: {res.reason}")
        meta = json.loads((path / "bundle.json").read_text(encoding="utf-8"))
        model_bytes = (path / meta.get("model_file", "model.txt")).read_bytes()
        if hashlib.sha256(model_bytes).hexdigest() != meta.get("model_sha256"):
            raise BundleError("model.txt does not match the hash recorded in bundle.json")
        if meta.get("feature_version") != FEATURE_VERSION:
            raise BundleError(f"Feature version mismatch: bundle {meta.get('feature_version')} vs runtime {FEATURE_VERSION}")
        booster = lgb.Booster(model_str=model_bytes.decode("utf-8"))
        if booster.num_feature() != meta.get("feature_dim"):
            raise BundleError("Booster feature count does not match bundle.json")
        return cls(path=path, meta=meta, booster=booster)

    def predict_proba(self, vectors: np.ndarray) -> np.ndarray:
        X = np.atleast_2d(np.asarray(vectors, dtype=np.float32))
        margin = self.booster.predict(X, raw_score=True)
        cal = self.meta["calibration"]
        return 1.0 / (1.0 + np.exp(-(cal["a"] * margin + cal["b"])))

    def file_sha256(self) -> str:
        return self.meta["model_sha256"]
