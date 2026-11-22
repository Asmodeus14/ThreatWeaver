"""Builds the EMBER2024 v3 (thrember, 2,568-D) training/evaluation dataset.

    python tools/build_ember_v3_dataset.py --file-types Win64 Dot_Net
    python tools/build_ember_v3_dataset.py --verify          # re-hash outputs against manifest

Requires the `ember` extra (thrember). Reads data/ember2024/<FileType>_{train,test}/ and
challenge/, writes data/ember_v3/ (git-ignored) plus a copy of the manifest to
artifacts/dataset/ember_v3_manifest.json (tracked).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from threatweaver.data.ember_v3_dataset import build_dataset, verify_outputs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="data/ember2024")
    ap.add_argument("--out-dir", default="data/ember_v3")
    ap.add_argument("--file-types", nargs="+", default=["Win64", "Dot_Net"], choices=["Win32", "Win64", "Dot_Net"])
    ap.add_argument("--val-weeks", type=int, default=8)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--max-rows-per-split", type=int, default=None, help="Random subsample per split (smoke runs)")
    ap.add_argument("--manifest-copy", default="artifacts/dataset/ember_v3_manifest.json")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()

    if args.verify:
        bad = verify_outputs(Path(args.out_dir))
        print("[+] All outputs match manifest" if not bad else f"[!] Modified outputs: {bad}")
        return 1 if bad else 0

    manifest = build_dataset(
        Path(args.data_dir), Path(args.out_dir), file_types=args.file_types,
        val_weeks=args.val_weeks, workers=args.workers, max_rows_per_split=args.max_rows_per_split,
        log=lambda m: print(m, flush=True),
    )
    copy = Path(args.manifest_copy)
    copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(Path(args.out_dir) / "manifest.json", copy)
    print(json.dumps({k: manifest[k] for k in ("splits", "scan_stats", "family_overlap")}, indent=2))
    print(f"[+] Manifest copied to {copy}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
