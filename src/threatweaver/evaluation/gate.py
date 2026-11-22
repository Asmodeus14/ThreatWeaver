"""Model regression gate: may a candidate model replace the current one?

Compares two eval/1 artifacts measured on the SAME test split (dataset manifest hash must
match) and fails when the candidate is measurably worse:

* detection rate at 1% FPR drops by more than ``max_tpr_drop`` (default 1 point), or
* detection rate at 0.1% FPR drops by more than ``max_tpr_drop_strict`` (default 2 points), or
* realised test FPR at the review threshold rises by more than ``max_fpr_rise`` (default 0.1 point), or
* challenge-set detection at the review threshold drops by more than ``max_challenge_drop`` (5 points).

Used before activating a retrained or locally adapted model (roadmap 7.1) and in CI.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class GateResult:
    passed: bool
    comparable: bool
    checks: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _metrics(ev: Dict[str, Any]) -> Dict[str, Optional[float]]:
    test = (ev.get("splits") or {}).get("test") or {}
    curve = test.get("tpr_at_fpr_curve") or {}
    ops = test.get("operating_points") or {}
    review = ops.get("tau_low_fpr_1pct") or ops.get("val_fpr_1pct") or {}
    chal = ((ev.get("splits") or {}).get("challenge") or {}).get("detection_at") or {}
    return {
        "tpr_at_1pct_fpr": curve.get("0.01"),
        "tpr_at_0.1pct_fpr": curve.get("0.001"),
        "review_threshold_test_fpr": review.get("fpr"),
        "challenge_detection_review": chal.get("tau_low_fpr_1pct"),
    }


def compare(candidate: Dict[str, Any], baseline: Dict[str, Any], *, max_tpr_drop: float = 0.01,
            max_tpr_drop_strict: float = 0.02, max_fpr_rise: float = 0.001,
            max_challenge_drop: float = 0.05) -> GateResult:
    c_ds = (candidate.get("dataset") or {}).get("manifest_sha256")
    b_ds = (baseline.get("dataset") or {}).get("manifest_sha256")
    if not c_ds or c_ds != b_ds:
        return GateResult(False, False, reason="Evaluations used different test data (dataset manifest hashes differ); "
                                                 "re-evaluate both models on the same split before comparing.")
    c, b = _metrics(candidate), _metrics(baseline)
    rules = [
        ("tpr_at_1pct_fpr", "higher", max_tpr_drop),
        ("tpr_at_0.1pct_fpr", "higher", max_tpr_drop_strict),
        ("review_threshold_test_fpr", "lower", max_fpr_rise),
        ("challenge_detection_review", "higher", max_challenge_drop),
    ]
    checks, passed = [], True
    for name, better, tol in rules:
        cv, bv = c.get(name), b.get(name)
        if cv is None or bv is None:
            checks.append({"metric": name, "status": "skipped", "candidate": cv, "baseline": bv})
            continue
        delta = cv - bv
        ok = delta >= -tol if better == "higher" else delta <= tol
        passed &= ok
        checks.append({"metric": name, "status": "pass" if ok else "fail", "candidate": cv, "baseline": bv,
                       "delta": delta, "tolerance": tol, "better": better})
    failed = [x["metric"] for x in checks if x["status"] == "fail"]
    return GateResult(passed, True, checks, "All checks passed." if passed else f"Regressed on: {', '.join(failed)}")


def compare_files(candidate_path: str | Path, baseline_path: str | Path, **kw) -> GateResult:
    load = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))  # noqa: E731
    return compare(load(candidate_path), load(baseline_path), **kw)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Fail if a candidate model regresses against the baseline.")
    ap.add_argument("candidate")
    ap.add_argument("baseline")
    args = ap.parse_args(argv)
    res = compare_files(args.candidate, args.baseline)
    print(json.dumps(res.to_dict(), indent=2))
    return 0 if res.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
