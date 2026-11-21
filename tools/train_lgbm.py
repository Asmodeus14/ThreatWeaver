"""Train the primary LightGBM detector on EMBER2024 v3 features and evaluate it.

    python tools/train_lgbm.py --data-dir data/ember_v3 --name lgbm-v3-win64-dotnet

Protocol
* train on the `train` split; model selection / calibration / thresholds use ONLY `val`
  (last weeks of the train window); `test` (later, official test partitions) and
  `challenge` are scored once at the end.
* starting hyper-parameters follow the EMBER2024 paper baseline (500 rounds, 64 leaves,
  min_data_in_leaf 100); thrember's categorical feature indices are honoured.
* calibration: Platt scaling of the raw margin on validation (monotonic -> ranking kept).
* operating points: tau_high = 0.1% FPR and tau_low = 1% FPR, both chosen on validation.

Outputs artifacts/models/<name>/: model.txt (LightGBM text format, no pickle),
bundle.json (feature version, calibration, thresholds, dataset manifest hash), eval.json,
each Ed25519-signed with the local key (release-sign later with tools/sign_release_checkpoints.py).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np

CATEGORICAL = [2, 3, 4, 5, 6, 701, 702]


def platt_fit(margins: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    from sklearn.linear_model import LogisticRegression
    lr = LogisticRegression(C=1e6, max_iter=1000)
    lr.fit(margins.reshape(-1, 1), y)
    return float(lr.coef_[0, 0]), float(lr.intercept_[0])


def platt_apply(margins: np.ndarray, a: float, b: float) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-(a * margins + b)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="data/ember_v3")
    ap.add_argument("--name", default="lgbm-v3")
    ap.add_argument("--rounds", type=int, default=500)
    ap.add_argument("--num-leaves", type=int, default=64)
    ap.add_argument("--min-data-in-leaf", type=int, default=100)
    ap.add_argument("--learning-rate", type=float, default=0.1)
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out-root", default="artifacts/models")
    args = ap.parse_args()

    import lightgbm as lgb
    from threatweaver.data.ember_v3_dataset import load_split, verify_outputs
    from threatweaver.evaluation.harness import binary_report, drift_report, threshold_for_fpr, rates_at_threshold, write_eval
    from threatweaver.models import signing
    from threatweaver.scanner.ember_v3 import FEATURE_VERSION

    data_dir = Path(args.data_dir)
    out = Path(args.out_root) / args.name
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = data_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bad = verify_outputs(data_dir)
    if bad:
        print(f"[!] Dataset files changed since the manifest was written: {bad}")
        return 1

    X_tr, y_tr, _ = load_split(data_dir, "train")
    X_va, y_va, m_va = load_split(data_dir, "val")
    print(f"[*] train {X_tr.shape}, val {X_va.shape}")

    params = {
        "objective": "binary", "metric": ["auc", "binary_logloss"], "num_leaves": args.num_leaves,
        "min_data_in_leaf": args.min_data_in_leaf, "learning_rate": args.learning_rate,
        "num_threads": args.threads, "seed": args.seed, "deterministic": True, "verbose": -1,
    }
    t0 = time.time()
    dtrain = lgb.Dataset(np.asarray(X_tr), y_tr, categorical_feature=CATEGORICAL, free_raw_data=True)
    dval = lgb.Dataset(np.asarray(X_va), y_va, reference=dtrain, categorical_feature=CATEGORICAL)
    evals = {}
    booster = lgb.train(params, dtrain, num_boost_round=args.rounds, valid_sets=[dval], valid_names=["val"],
                        callbacks=[lgb.record_evaluation(evals), lgb.log_evaluation(50)])
    train_sec = time.time() - t0
    print(f"[+] trained {booster.num_trees()} trees in {train_sec:.0f}s")

    def margins(X):
        return booster.predict(np.asarray(X), raw_score=True)

    mv = margins(X_va)
    a, b = platt_fit(mv, y_va)
    p_va = platt_apply(mv, a, b)
    thresholds = {"tau_high_fpr_0.1pct": threshold_for_fpr(y_va, p_va, 0.001),
                  "tau_low_fpr_1pct": threshold_for_fpr(y_va, p_va, 0.01)}

    splits = {"val": binary_report(y_va, p_va, thresholds=thresholds)}
    timing = {}
    for name in ("test", "challenge"):
        if name not in manifest["splits"]:
            continue
        X, y, meta = load_split(data_dir, name)
        t1 = time.time()
        p = platt_apply(margins(X), a, b)
        timing[f"{name}_ms_per_sample"] = (time.time() - t1) * 1000 / max(len(y), 1)
        if name == "challenge":  # malicious only: detection rates at the fixed thresholds
            splits[name] = {"n": int(len(y)), "detection_at": {k: float(np.mean(p >= v)) for k, v in thresholds.items()}}
            continue
        rep = binary_report(y, p, thresholds=thresholds)
        ft = np.array(meta["file_type"].to_list())
        rep["by_file_type"] = {t: binary_report(y[ft == t], p[ft == t], thresholds=thresholds, n_boot=50)
                               for t in np.unique(ft) if (y[ft == t] == 0).any() and (y[ft == t] == 1).any()}
        for t in rep["by_file_type"].values():  # keep per-type blocks compact
            for k in ("roc_curve", "pr_curve", "reliability", "score_histogram"):
                t.pop(k, None)
        rep["drift_tau_low"] = drift_report(y, p, np.array(meta["first_submission_date"].to_list(), dtype=np.int64),
                                            thresholds["tau_low_fpr_1pct"], period_days=14)
        splits[name] = rep

    model_path = out / "model.txt"
    booster.save_model(str(model_path))
    gain = booster.feature_importance(importance_type="gain")
    top = [{"feature": int(i), "gain": float(gain[i])} for i in np.argsort(gain)[::-1][:40]]
    bundle = {
        "id": args.name, "kind": "lightgbm-binary", "feature_version": FEATURE_VERSION, "feature_dim": int(X_va.shape[1]),
        "model_file": "model.txt", "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "calibration": {"method": "platt_on_raw_margin", "a": a, "b": b, "fit_on": "val"},
        "thresholds": thresholds, "params": params, "num_trees": booster.num_trees(), "train_seconds": round(train_sec, 1),
        "dataset_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "dataset_splits": manifest["splits"], "top_features_by_gain": top,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (out / "bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    write_eval(out / "eval.json", kind="benchmark",
               model={"id": args.name, "model_sha256": bundle["model_sha256"], "feature_version": FEATURE_VERSION,
                      "thresholds": thresholds, "calibration": bundle["calibration"]},
               dataset={"manifest_sha256": bundle["dataset_manifest_sha256"], "split_definition": manifest["split_definition"],
                        "file_types": manifest["file_types"]},
               splits=splits, extra={"timing": timing, "val_auc_curve": evals.get("val", {}).get("auc", [])[-1:]})
    for f in ("model.txt", "bundle.json", "eval.json"):
        signing.sign_file(out / f, role="local")

    t = splits.get("test", {})
    print(json.dumps({
        "val_roc_auc": splits["val"]["roc_auc"],
        "test_roc_auc": t.get("roc_auc"), "test_pr_auc": t.get("pr_auc"),
        "test_tpr_at_fpr_curve": t.get("tpr_at_fpr_curve"),
        "test_operating_points": {k: {m: v[m] for m in ("threshold", "tpr", "fpr")} for k, v in t.get("operating_points", {}).items()},
        "challenge": splits.get("challenge"), "timing": timing,
    }, indent=2))
    print(f"[+] Bundle written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
