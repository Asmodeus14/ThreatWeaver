"""Neural model + novelty study on EMBER2024 v3 features (roadmap 3.2 / 3.3).

    python tools/train_mlp_v3.py --data-dir data/ember_v3 --name mlp-v3 [--lgbm artifacts/models/lgbm-v3]

* Residual MLP on signed-log1p + standardized 2,568-D features (statistics from train only),
  64-D L2-normalized embedding, cross-entropy, AdamW + cosine schedule, temperature fitted on val.
* Detection compared with the LightGBM bundle on the SAME test split (bootstrap CIs on
  TPR@0.1%/1% FPR); a score-average ensemble is evaluated but only recommended if it wins.
* Novelty: kNN cosine distance to a train reference bank vs. Mahalanobis (shared covariance)
  vs. energy score. OOD sets = malware from families absent from train, and the challenge set.
  The method is SELECTED on the validation split and REPORTED on test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn


def signed_log1p(x: np.ndarray) -> np.ndarray:
    return np.sign(x) * np.log1p(np.abs(x))


class Prep:
    def __init__(self, mean, std):
        self.mean, self.std = mean.astype(np.float32), std.astype(np.float32)

    @classmethod
    def fit(cls, X: np.ndarray, rows: int = 60000, seed: int = 0):
        rng = np.random.default_rng(seed)
        idx = np.sort(rng.choice(len(X), size=min(rows, len(X)), replace=False))
        Z = signed_log1p(np.asarray(X[idx], dtype=np.float64))
        std = Z.std(0)
        std[std < 1e-6] = 1.0
        return cls(Z.mean(0), std)

    def __call__(self, X) -> np.ndarray:
        return ((signed_log1p(np.asarray(X, dtype=np.float32)) - self.mean) / self.std).astype(np.float32)


def batched(model, prep, X, bs=4096):
    probs, embs, logits = [], [], []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(X), bs):
            out = model(torch.from_numpy(prep(X[i:i + bs])))
            probs.append(out.probabilities[:, 1].numpy())
            embs.append(out.embeddings.numpy())
            logits.append(out.logits.numpy())
    return np.concatenate(probs), np.concatenate(embs), np.concatenate(logits)


# ------------------------------------------------------------------ novelty scorers

class KNNScorer:
    def __init__(self, bank: np.ndarray, k: int = 10):
        self.bank = bank.astype(np.float32)
        self.k = k

    def __call__(self, E: np.ndarray, bs: int = 2048) -> np.ndarray:
        out = []
        for i in range(0, len(E), bs):
            sims = E[i:i + bs] @ self.bank.T
            topk = np.partition(-sims, self.k - 1, axis=1)[:, :self.k]
            out.append(1.0 + topk.mean(1))  # mean cosine distance to k nearest
        return np.concatenate(out)


class MahalanobisScorer:
    def __init__(self, E: np.ndarray, y: np.ndarray):
        self.means = np.stack([E[y == c].mean(0) for c in (0, 1)])
        centered = np.concatenate([E[y == c] - self.means[c] for c in (0, 1)])
        cov = np.cov(centered, rowvar=False) + 1e-4 * np.eye(E.shape[1])
        self.prec = np.linalg.inv(cov)

    def __call__(self, E: np.ndarray) -> np.ndarray:
        d = [np.einsum("ij,jk,ik->i", E - m, self.prec, E - m) for m in self.means]
        return np.minimum(*d)


def energy_score(logits: np.ndarray) -> np.ndarray:
    m = logits.max(1, keepdims=True)
    return -(m[:, 0] + np.log(np.exp(logits - m).sum(1)))  # higher = more unfamiliar


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="data/ember_v3")
    ap.add_argument("--name", default="mlp-v3")
    ap.add_argument("--lgbm", default=None, help="LightGBM bundle directory to compare / ensemble with")
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--batch", type=int, default=1024)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--embedding-dim", type=int, default=64)
    ap.add_argument("--bank", type=int, default=50000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--out-root", default="artifacts/models")
    args = ap.parse_args()

    from threatweaver.data.ember_v3_dataset import load_split, verify_outputs
    from threatweaver.evaluation.harness import (binary_report, bootstrap_ci, novelty_report, threshold_for_fpr,
                                                 tpr_at_fpr, write_eval)
    from threatweaver.models import signing
    from threatweaver.models.calibration import calibrate_temperature
    from threatweaver.models.classifier import ThreatClassifier, save_checkpoint
    from threatweaver.scanner.ember_v3 import FEATURE_VERSION

    torch.manual_seed(args.seed)
    torch.set_num_threads(args.threads)
    data_dir = Path(args.data_dir)
    if verify_outputs(data_dir):
        print("[!] dataset outputs changed since manifest")
        return 1
    manifest_path = data_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    out = Path(args.out_root) / args.name
    out.mkdir(parents=True, exist_ok=True)

    X_tr, y_tr, m_tr = load_split(data_dir, "train")
    X_va, y_va, m_va = load_split(data_dir, "val")
    X_te, y_te, m_te = load_split(data_dir, "test")
    prep = Prep.fit(X_tr, seed=args.seed)

    model = ThreatClassifier(input_dim=X_tr.shape[1], hidden_dims=[512, 512, 512, 256, 256],
                             embedding_dim=args.embedding_dim, num_classes=2, dropout=0.1)
    n_res = sum(1 for m in model.modules() if m.__class__.__name__ == "ResidualBlock")
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    steps = args.epochs * int(np.ceil(len(y_tr) / args.batch))
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=args.lr, total_steps=steps, pct_start=0.1)
    lossf = nn.CrossEntropyLoss()
    rng = np.random.default_rng(args.seed)
    t0 = time.time()
    best = (-1.0, None)
    for ep in range(args.epochs):
        model.train()
        perm = rng.permutation(len(y_tr))
        for i in range(0, len(perm), args.batch):
            idx = np.sort(perm[i:i + args.batch])
            xb = torch.from_numpy(prep(X_tr[idx]))
            yb = torch.from_numpy(y_tr[idx].astype(np.int64))
            opt.zero_grad()
            loss = lossf(model(xb).logits, yb)
            loss.backward()
            opt.step()
            sched.step()
        p_va, _, _ = batched(model, prep, X_va)
        auc_tpr = tpr_at_fpr(y_va, p_va, 0.01)
        print(f"  epoch {ep + 1}/{args.epochs}: val TPR@1%FPR={auc_tpr:.4f}  ({time.time() - t0:.0f}s)", flush=True)
        if auc_tpr > best[0]:
            best = (auc_tpr, {k: v.clone() for k, v in model.state_dict().items()})
    model.load_state_dict(best[1])
    train_sec = time.time() - t0

    # temperature on val logits (calibration only; ranking unchanged)
    _, _, logit_va = batched(model, prep, X_va)
    model.temperature = calibrate_temperature(logit_va, y_va.astype(np.int64))
    p_va, e_va, logit_va = batched(model, prep, X_va)
    p_te, e_te, logit_te = batched(model, prep, X_te)
    thr = {"tau_high_fpr_0.1pct": threshold_for_fpr(y_va, p_va, 0.001), "tau_low_fpr_1pct": threshold_for_fpr(y_va, p_va, 0.01)}
    splits = {"val": binary_report(y_va, p_va, thresholds=thr), "test": binary_report(y_te, p_te, thresholds=thr)}

    # ---- comparison / ensemble with LightGBM on identical rows
    comparison = None
    if args.lgbm:
        from threatweaver.models.bundle import LGBMBundle
        b = LGBMBundle.load(args.lgbm)
        q_va, q_te = b.predict_proba(np.asarray(X_va)), b.predict_proba(np.asarray(X_te))
        ens_va, ens_te = (p_va + q_va) / 2, (p_te + q_te) / 2
        comparison = {}
        for name, (sv, st) in {"mlp": (p_va, p_te), "lightgbm": (q_va, q_te), "ensemble_mean": (ens_va, ens_te)}.items():
            comparison[name] = {
                f"test_tpr_at_fpr_{t:g}": {"value": tpr_at_fpr(y_te, st, t),
                                           "ci95": bootstrap_ci(lambda a, s, t=t: tpr_at_fpr(a, s, t), y_te, st, 200)}
                for t in (0.001, 0.01)
            }
            comparison[name]["val_tpr_at_fpr_0.01"] = tpr_at_fpr(y_va, sv, 0.01)

    # ---- novelty
    tr_fams = set(m_tr["family"].drop_nulls().to_list())
    def unseen(meta, y):
        fam = np.array([f if f is not None else "" for f in meta["family"].to_list()])
        return (y == 1) & (fam != "") & ~np.isin(fam, list(tr_fams))
    bank_idx = np.sort(rng.choice(len(y_tr), size=min(args.bank, len(y_tr)), replace=False))
    _, e_bank, _ = batched(model, prep, X_tr[bank_idx])
    scorers = {
        "knn10_cosine": (lambda E, L: KNNScorer(e_bank, 10)(E)),
        "mahalanobis": (lambda E, L, M=MahalanobisScorer(e_bank, y_tr[bank_idx]): M(E)),
        "energy": (lambda E, L: energy_score(L)),
    }
    nov = {"method_selected_on": "val unseen-family malware vs val benign", "methods": {}}
    va_unseen, te_unseen = unseen(m_va, y_va), unseen(m_te, y_te)
    chal = None
    if "challenge" in manifest["splits"]:
        X_ch, _, _ = load_split(data_dir, "challenge")
        _, e_ch, l_ch = batched(model, prep, X_ch)
        chal = (e_ch, l_ch)
    for name, fn in scorers.items():
        s_va, s_te = fn(e_va, logit_va), fn(e_te, logit_te)
        entry = {"val_unseen_family": novelty_report(s_va[y_va == 0], s_va[va_unseen]) if va_unseen.any() else None,
                 "test_unseen_family": novelty_report(s_te[y_te == 0], s_te[te_unseen]) if te_unseen.any() else None,
                 "tau_val_benign_p95": float(np.percentile(s_va[y_va == 0], 95))}
        if chal is not None:
            entry["test_challenge"] = novelty_report(s_te[y_te == 0], fn(*chal))
        nov["methods"][name] = entry
    ranked = sorted(nov["methods"], key=lambda k: (nov["methods"][k]["val_unseen_family"] or {}).get("auroc", 0), reverse=True)
    nov["selected"] = ranked[0]
    nov["counts"] = {"val_unseen_family_malware": int(va_unseen.sum()), "test_unseen_family_malware": int(te_unseen.sum())}

    ckpt = out / "model.pt"
    save_checkpoint(model, ckpt, feature_mean=prep.mean.tolist(), feature_std=prep.std.tolist(),
                    metadata={"feature_version": FEATURE_VERSION, "preprocessing": "signed_log1p+standardize",
                              "thresholds": thr, "residual_blocks": n_res, "train_seconds": round(train_sec, 1)})
    np.save(out / "reference_bank.npy", e_bank.astype(np.float16))
    signing.sign_file(out / "reference_bank.npy")
    write_eval(out / "eval.json", kind="benchmark",
               model={"id": args.name, "type": f"residual MLP ({n_res} residual blocks), {args.embedding_dim}-D embedding",
                      "checkpoint_sha256": hashlib.sha256(ckpt.read_bytes()).hexdigest(), "feature_version": FEATURE_VERSION,
                      "temperature": model.temperature, "thresholds": thr},
               dataset={"manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                        "split_definition": manifest["split_definition"], "file_types": manifest["file_types"]},
               splits=splits, extra={"comparison_with_lightgbm": comparison, "novelty": nov})
    signing.sign_file(out / "eval.json")

    print(json.dumps({"residual_blocks": n_res, "train_seconds": round(train_sec), "test_roc_auc": splits["test"]["roc_auc"],
                      "test_tpr_at_fpr": splits["test"]["tpr_at_fpr_curve"], "comparison": comparison,
                      "novelty": {k: {kk: (vv or {}).get("auroc") for kk, vv in v.items() if isinstance(vv, dict) or vv is None}
                                  for k, v in nov["methods"].items()}, "selected": nov["selected"], "counts": nov["counts"]},
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
