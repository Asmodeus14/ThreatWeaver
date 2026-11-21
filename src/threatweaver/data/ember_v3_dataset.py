"""EMBER2024 v3 dataset pipeline: filter, dedupe, vectorize (thrember), split, manifest.

Output layout (``out_dir``, default ``data/ember_v3``, git-ignored):

    X_<split>.dat        float32 memmap, shape (n, 2568)
    y_<split>.npy        int8 labels (0 benign, 1 malicious)
    meta_<split>.parquet sha256, tlsh, first_submission_date, file_type, family,
                         family_confidence, label, partition, source_file
    manifest.json        row counts, source-file SHA-256s, feature version, split
                         definition and the SHA-256 of every output file

Splits
    train      official *_train partitions, minus the validation window
    val        last ``val_weeks`` weeks of the train window (temporal hold-out)
    test       official *_test partitions (strictly later than train)
    challenge  evasive malware set (malicious only)

The split definition is stored in the manifest; any change produces a different
manifest hash, so evaluation methodology cannot change silently.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

PE_FILE_TYPES = ("Win32", "Win64", "Dot_Net")
PREFIX_MARKER = b', "histogram"'
META_FIELDS = ("sha256", "tlsh", "first_submission_date", "file_type", "family", "family_confidence", "label")


def parse_metadata_prefix(line: bytes | str) -> Optional[dict]:
    """Parses only the metadata fields preceding the large feature payload of a record."""
    if isinstance(line, str):
        line = line.encode("utf-8", errors="replace")
    cut = line.find(PREFIX_MARKER)
    text = (line[:cut] + b"}") if cut > 0 else line
    try:
        return json.loads(text)
    except ValueError:
        try:
            return json.loads(line)
        except ValueError:
            return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Row:
    split: str
    source_idx: int
    offset: int
    meta: dict


@dataclass
class ScanStats:
    records: int = 0
    unparseable: int = 0
    unlabeled: int = 0
    non_pe: int = 0
    wrong_file_type: int = 0
    duplicates: int = 0
    duplicate_examples: List[str] = field(default_factory=list)


def scan_metadata(
    sources: Sequence[Tuple[str, Path]],
    file_types: Iterable[str],
    stats: ScanStats,
) -> List[Row]:
    """Pass 1: keep labelled, non-duplicate PE records of the requested file types."""
    wanted = set(file_types)
    seen: Dict[str, str] = {}
    rows: List[Row] = []
    for idx, (split, path) in enumerate(sources):
        offset = 0
        with open(path, "rb") as f:
            for line in f:
                start, offset = offset, offset + len(line)
                if not line.strip():
                    continue
                stats.records += 1
                meta = parse_metadata_prefix(line)
                if meta is None:
                    stats.unparseable += 1
                    continue
                if meta.get("label") not in (0, 1):
                    stats.unlabeled += 1
                    continue
                ft = meta.get("file_type")
                if ft not in PE_FILE_TYPES:
                    stats.non_pe += 1
                    continue
                if ft not in wanted:
                    stats.wrong_file_type += 1
                    continue
                sha = meta.get("sha256")
                if sha in seen:
                    stats.duplicates += 1
                    if len(stats.duplicate_examples) < 20:
                        stats.duplicate_examples.append(f"{sha} ({seen[sha]} & {split})")
                    continue
                seen[sha] = split
                rows.append(Row(split, idx, start, {k: meta.get(k) for k in META_FIELDS}))
    return rows


# ------------------------------------------------------------------ pass 2 (workers)

_worker_ext = None


def _init_worker():
    global _worker_ext
    from threatweaver.scanner.ember_v3 import EmberV3Extractor
    _worker_ext = EmberV3Extractor()


def _vectorize_job(job: Tuple[str, str, int, List[Tuple[int, int]]]) -> Tuple[int, int]:
    """Vectorizes a batch of (row_index, byte_offset) from one source file into the memmap."""
    src_path, x_path, n_rows, items = job
    X = np.memmap(x_path, dtype=np.float32, mode="r+", shape=(n_rows, 2568))
    failures = 0
    with open(src_path, "rb") as f:
        for row_idx, offset in items:
            f.seek(offset)
            line = f.readline()
            try:
                X[row_idx] = _worker_ext.vector_from_record(json.loads(line))
            except Exception:
                X[row_idx] = 0.0
                failures += 1
    X.flush()
    del X
    return len(items), failures


def build_dataset(
    data_dir: Path,
    out_dir: Path,
    file_types: Sequence[str] = ("Win64", "Dot_Net"),
    val_weeks: int = 8,
    workers: Optional[int] = None,
    batch_size: int = 2000,
    max_rows_per_split: Optional[int] = None,
    log=print,
) -> dict:
    import polars as pl
    from threatweaver.scanner.ember_v3 import FEATURE_DIM, FEATURE_VERSION

    data_dir, out_dir = Path(data_dir).resolve(), Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    partitions = {
        "train": [f"{ft}_train" for ft in file_types],
        "test": [f"{ft}_test" for ft in file_types],
        "challenge": ["challenge"],
    }
    sources: List[Tuple[str, Path]] = []
    for split, parts in partitions.items():
        for part in parts:
            files = sorted((data_dir / part).glob("*.jsonl"))
            if not files:
                log(f"[!] No files for partition {part} (skipped)")
            sources.extend((split, f) for f in files)
    if not any(s == "train" for s, _ in sources):
        raise FileNotFoundError(f"No *_train partitions for {file_types} under {data_dir}")

    t0 = time.time()
    stats = ScanStats()
    rows = scan_metadata(sources, file_types, stats)
    log(f"[+] Metadata pass: {stats.records:,} records -> {len(rows):,} kept ({time.time() - t0:.0f}s)")

    # Temporal validation window = last `val_weeks` weeks of the train window
    train_ts = [r.meta["first_submission_date"] or 0 for r in rows if r.split == "train"]
    cutoff = int(max(train_ts)) - val_weeks * 7 * 86400
    for r in rows:
        if r.split == "train" and (r.meta["first_submission_date"] or 0) > cutoff:
            r.split = "val"

    by_split: Dict[str, List[Row]] = {}
    for r in rows:
        by_split.setdefault(r.split, []).append(r)
    if max_rows_per_split:
        rng = np.random.default_rng(0)
        for k, v in by_split.items():
            if len(v) > max_rows_per_split:
                keep = np.sort(rng.choice(len(v), size=max_rows_per_split, replace=False))
                by_split[k] = [v[i] for i in keep]

    workers = workers or max(1, (os.cpu_count() or 2) - 2)
    outputs = {}
    ctx = mp.get_context("spawn")
    with ctx.Pool(workers, initializer=_init_worker) as pool:
        for split in ("train", "val", "test", "challenge"):
            split_rows = by_split.get(split, [])
            if not split_rows:
                continue
            n = len(split_rows)
            x_path = out_dir / f"X_{split}.dat"
            np.memmap(x_path, dtype=np.float32, mode="w+", shape=(n, FEATURE_DIM)).flush()
            jobs: Dict[int, List[Tuple[int, int]]] = {}
            for i, r in enumerate(split_rows):
                jobs.setdefault(r.source_idx, []).append((i, r.offset))
            batches = []
            for src_idx, items in jobs.items():
                for b in range(0, len(items), batch_size):
                    batches.append((str(sources[src_idx][1]), str(x_path), n, items[b:b + batch_size]))
            done = failed = 0
            t1 = time.time()
            for cnt, fails in pool.imap_unordered(_vectorize_job, batches):
                done += cnt
                failed += fails
                log(f"    {split}: {done:,}/{n:,} vectorized ({done / max(time.time() - t1, 1e-3):,.0f}/s)")
            y = np.array([r.meta["label"] for r in split_rows], dtype=np.int8)
            np.save(out_dir / f"y_{split}.npy", y)
            meta = pl.DataFrame({
                **{k: [r.meta[k] for r in split_rows] for k in META_FIELDS},
                "partition": [sources[r.source_idx][1].parent.name for r in split_rows],
                "source_file": [sources[r.source_idx][1].name for r in split_rows],
            })
            meta.write_parquet(out_dir / f"meta_{split}.parquet")
            outputs[split] = {"rows": n, "benign": int((y == 0).sum()), "malicious": int((y == 1).sum()),
                              "vectorize_failures": failed}
            log(f"[+] {split}: {n:,} rows ({outputs[split]['benign']:,} benign / {outputs[split]['malicious']:,} malicious, {failed} failures)")

    # Family overlap between train and test (leakage / novelty context)
    fam = {s: {r.meta["family"] for r in by_split.get(s, []) if r.meta["family"]} for s in ("train", "test")}
    manifest = {
        "feature_version": FEATURE_VERSION,
        "feature_dim": FEATURE_DIM,
        "file_types": list(file_types),
        "split_definition": {
            "train": partitions["train"], "test": partitions["test"], "challenge": partitions["challenge"],
            "val": f"last {val_weeks} weeks of train window (first_submission_date > {cutoff})",
            "val_cutoff_unix": cutoff, "dedupe": "exact sha256, first occurrence kept",
            "max_rows_per_split": max_rows_per_split,
        },
        "scan_stats": stats.__dict__,
        "splits": outputs,
        "family_overlap": {
            "train_families": len(fam["train"]), "test_families": len(fam["test"]),
            "test_families_unseen_in_train": len(fam["test"] - fam["train"]),
        },
        "source_files": {str(p.relative_to(data_dir)): sha256_file(p) for _, p in sources},
        "output_files": {},
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_sec": round(time.time() - t0, 1),
    }
    for f in sorted(out_dir.glob("*")):
        if f.suffix in (".dat", ".npy", ".parquet"):
            manifest["output_files"][f.name] = sha256_file(f)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def load_split(out_dir: Path, split: str):
    """Returns (X memmap, y, metadata DataFrame) for a split; verifies files against the manifest."""
    import polars as pl

    out_dir = Path(out_dir)
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    n = manifest["splits"][split]["rows"]
    X = np.memmap(out_dir / f"X_{split}.dat", dtype=np.float32, mode="r", shape=(n, manifest["feature_dim"]))
    y = np.load(out_dir / f"y_{split}.npy")
    meta = pl.read_parquet(out_dir / f"meta_{split}.parquet")
    return X, y, meta


def verify_outputs(out_dir: Path) -> List[str]:
    """Returns a list of output files whose SHA-256 no longer matches the manifest."""
    out_dir = Path(out_dir)
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    return [name for name, digest in manifest["output_files"].items() if sha256_file(out_dir / name) != digest]
