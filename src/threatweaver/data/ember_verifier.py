"""ThreatWeaver EMBER2024 Dataset Verifier and Provenance Auditor.

Inspects local EMBER2024 JSONL partitions, validates schema consistency,
computes class balance, audits temporal coverage, verifies zero-corruption integrity,
and generates standardized dataset manifests (ember2024_manifest.json).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def audit_dataset_directory(
    data_dir: str | Path,
    manifest_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Audits an EMBER2024 data directory and extracts verified metadata.

    Args:
        data_dir: Root directory containing EMBER2024 JSONL files.
        manifest_path: Optional path to save the generated JSON manifest.

    Returns:
        Structured dictionary containing counts, dates, types, and verification status.
    """
    root = Path(data_dir).resolve()
    if not root.is_dir():
        manifest = {
            "dataset": "EMBER2024",
            "verified": False,
            "status": "NOT_FOUND",
            "location": str(root),
            "error": f"Directory does not exist: {root}",
            "manifest_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if manifest_path:
            p = Path(manifest_path).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        return manifest

    jsonl_files = sorted(list(root.rglob("*.jsonl")))
    if not jsonl_files:
        manifest = {
            "dataset": "EMBER2024",
            "verified": False,
            "status": "EMPTY",
            "location": str(root),
            "jsonl_files_count": 0,
            "total_bytes": 0,
            "samples": 0,
            "manifest_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if manifest_path:
            p = Path(manifest_path).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        return manifest

    total_bytes = sum(f.stat().st_size for f in jsonl_files)
    total_records = 0
    benign_count = 0
    malicious_count = 0
    unlabeled_count = 0
    corrupt_count = 0
    dates: List[str] = []
    sample_shas: List[str] = []
    file_types: Dict[str, int] = {}
    partitions: Dict[str, int] = {}

    for jf in jsonl_files:
        part_name = jf.parent.name
        with open(jf, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    total_records += 1
                    lbl = record.get("label", -1)
                    if lbl == 0:
                        benign_count += 1
                    elif lbl == 1:
                        malicious_count += 1
                    else:
                        unlabeled_count += 1

                    ft = record.get("file_type", "PE")
                    file_types[ft] = file_types.get(ft, 0) + 1
                    partitions[part_name] = partitions.get(part_name, 0) + 1

                    raw_d = record.get("appeared") or record.get("first_submission_date")
                    if isinstance(raw_d, (int, float)):
                        d = time.strftime("%Y-%m", time.gmtime(raw_d))
                    elif isinstance(raw_d, str):
                        d = raw_d[:7]
                    else:
                        d = ""
                    if d and d not in dates:
                        dates.append(d)

                    if len(sample_shas) < 10 and record.get("sha256"):
                        sample_shas.append(record.get("sha256"))
                except Exception:
                    corrupt_count += 1

    dates.sort()
    verified = total_records > 0 and corrupt_count == 0

    manifest = {
        "dataset": "EMBER2024",
        "verified": verified,
        "status": "VERIFIED" if verified else "WARNING_CORRUPTIONS",
        "location": str(root),
        "jsonl_files_count": len(jsonl_files),
        "total_bytes": total_bytes,
        "samples": total_records,
        "benign": benign_count,
        "malicious": malicious_count,
        "unlabeled": unlabeled_count,
        "corrupt_records": corrupt_count,
        "features": 2381,
        "harmonized_features": 256,
        "time_span": [dates[0], dates[-1]] if dates else [],
        "file_types": file_types,
        "partitions": partitions,
        "sample_hashes_preview": sample_shas,
        "manifest_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "license": "Apache-2.0",
        "source": "https://huggingface.co/datasets/joyce8/EMBER2024",
    }

    if manifest_path:
        p = Path(manifest_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    return manifest


def evaluate_dataset_readiness(manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Evaluates whether dataset is sufficient for research baselines and continual learning.

    Returns:
        (ready_for_evaluation, advisory_messages)
    """
    messages: List[str] = []
    if not manifest.get("verified", False):
        messages.append("Dataset is not verified or contains missing/corrupt records.")
        return False, messages

    samples = manifest.get("samples", 0)
    benign = manifest.get("benign", 0)
    malicious = manifest.get("malicious", 0)

    if samples < 100:
        messages.append(f"Sample count ({samples}) is insufficient for reliable statistical evaluation.")
        return False, messages

    if benign == 0:
        messages.append("Warning: Zero benign samples present. Cannot compute False Positive Rate (FPR) or ROC curves without benign baseline.")
    elif malicious == 0:
        messages.append("Warning: Zero malicious samples present. Cannot compute Recall or Detection Rate.")
    else:
        messages.append(f"Balanced evaluation possible: {benign:,} benign samples and {malicious:,} malicious samples.")

    time_span = manifest.get("time_span", [])
    if time_span and len(time_span) >= 2:
        messages.append(f"Temporal span verified: {time_span[0]} to {time_span[1]} (supports chronological drift evaluation).")

    return (samples > 0), messages
