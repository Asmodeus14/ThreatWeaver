"""Continuity check: re-score the shipped v0.1 128-D checkpoint on its original locked test
split with the new evaluation harness, and write artifacts/eval/legacy-v0.1-128d/eval.json.

The split is rebuilt exactly as tools/ablation_embedding_dimension.py did it (first records of
the earliest weekly files: 3,000 Win64 + 2,000 .NET + 500 challenge; 70/15/15 by timestamp).
Agreement with artifacts/benchmarks/selected_embedding_dimension.json proves the harness
reproduces the published numbers before it is used for anything new.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ablation_embedding_dimension import load_ablation_dataset  # noqa: E402

from threatweaver.data.preprocessing import FeatureScaler  # noqa: E402
from threatweaver.data.splits import TemporalSplitter  # noqa: E402
from threatweaver.evaluation.harness import binary_report, file_sha256, novelty_report, threshold_for_fpr, write_eval  # noqa: E402
from threatweaver.models.classifier import load_checkpoint  # noqa: E402
from threatweaver.models.novelty import NoveltyDetector, PrototypeCluster  # noqa: E402

CKPT = Path("artifacts/checkpoints/threatweaver_128d.pt")
PUBLISHED = Path("artifacts/benchmarks/selected_embedding_dimension.json")
OUT = Path("artifacts/eval/legacy-v0.1-128d/eval.json")


def main() -> int:
    X, y, ts, X_chal, _ = load_ablation_dataset(Path("data/ember2024"), 3000, 2000, 500)
    split = TemporalSplitter(0.70, 0.15, 0.15).split_by_timestamps(ts)
    model, meta = load_checkpoint(CKPT)
    scaler = FeatureScaler.from_dict({"fitted": True, "mean": meta["feature_mean"], "std": meta["feature_std"]})

    def score(Xraw):
        with torch.no_grad():
            out = model(torch.tensor(scaler.transform(Xraw), dtype=torch.float32))
        return out.probabilities[:, 1].numpy(), out.embeddings.numpy()

    p_val, _ = score(X[split.val_indices])
    p_test, e_test = score(X[split.test_indices])
    _, e_chal = score(X_chal)
    y_val, y_test = y[split.val_indices], y[split.test_indices]

    thresholds = {
        "default_0.5": 0.5,
        "val_fpr_1pct": threshold_for_fpr(y_val, p_val, 0.01),
    }
    test_rep = binary_report(y_test, p_test, thresholds=thresholds)
    val_rep = binary_report(y_val, p_val, thresholds=thresholds)

    det = NoveltyDetector(calibrated_threshold=meta["novelty_threshold"])
    det.prototypes = [PrototypeCluster(p["label"], p["family_name"], np.array(p["centroid"], np.float32), p["sample_count"])
                      for p in meta["prototypes"]]
    nov = novelty_report(det.score(e_test[y_test == 0]), det.score(e_chal))

    published = json.loads(PUBLISHED.read_text(encoding="utf-8"))["final_untouched_test_results"]
    comparison = {
        "macro_f1@0.5": (test_rep["operating_points"]["default_0.5"]["macro_f1"], published["macro_f1"]),
        "roc_auc": (test_rep["roc_auc"], published["roc_auc"]),
        "pr_auc": (test_rep["pr_auc"], published["pr_auc"]),
        "tpr@1%fpr": (test_rep["tpr_at_fpr_curve"]["0.01"], published["detection_rate_at_1pct_fpr"]),
        "novelty_auroc (benign test vs challenge)": (nov["auroc"], published["novelty_auroc"]),
    }
    write_eval(
        OUT, kind="benchmark",
        model={"id": "legacy-v0.1-128d", "checkpoint": str(CKPT), "checkpoint_sha256": file_sha256(CKPT),
               "features": "legacy 256-D harmonized (v0.1)", "temperature": meta.get("extra", {}).get("temperature")},
        dataset={"description": "v0.1 ablation split rebuilt exactly (first records of earliest weekly files)",
                 "win64": 3000, "dotnet": 2000, "challenge": 500, "split": "70/15/15 by first_submission_date",
                 "test_time_span_unix": [int(ts[split.test_indices].min()), int(ts[split.test_indices].max())]},
        splits={"val": val_rep, "test": test_rep, "novelty": nov},
        extra={"reproduction_vs_published": {k: {"harness": a, "published": b, "abs_diff": abs(a - b)}
                                             for k, (a, b) in comparison.items()},
               "caveats": ["Test split is 750 samples spanning ~30 hours; indicative only.",
                           "Legacy features suffer the train/serve mismatch documented in the model card.",
                           "Novelty AUROC here uses the SHIPPED detector (checkpoint's 10 prototypes/class). The "
                           "published 0.601 came from select_embedding_dimension.py, which refit 12 prototypes/class "
                           "and calibrated tau on the test benign set (test leakage for its tau-based metrics); "
                           "that detector was never deployed."]},
    )
    for k, (a, b) in comparison.items():
        print(f"  {k:42s} harness={a:.4f}  published={b:.4f}  diff={abs(a - b):.4f}")
    print(f"[+] Wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
