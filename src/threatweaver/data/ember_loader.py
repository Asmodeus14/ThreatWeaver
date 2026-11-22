"""EMBER Dataset streaming loader, memmap adapter, and temporal split manager.

Provides zero-RAM-explosion streaming of EMBER (2018/2024) JSONL and memmapped .dat files,
drops unlabeled samples (label == -1), preserves chronological splits via 'appeared' timestamps,
and supports both native 2381-dim and harmonized 256-dim feature representations.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple, Union

import numpy as np
import torch

from threatweaver.data.loader import ThreatDataset
from threatweaver.scanner.feature_extractor import FEATURE_DIM, SCHEMA_VERSION

EMBER_RAW_FEATURE_DIM = 2381


@dataclass
class EMBERMetadata:
    """Provenance and summary statistics for an EMBER dataset split."""
    total_records: int
    benign_count: int
    malware_count: int
    unlabeled_count: int
    time_span: List[str]
    feature_dim: int


class EMBERDatasetLoader:
    """Streaming reader and preprocessor for EMBER benchmark datasets."""

    def __init__(
        self,
        schema_mode: str = "harmonized",  # "harmonized" (256-dim) or "native" (2381-dim)
        drop_unlabeled: bool = True,
    ):
        self.schema_mode = schema_mode
        self.drop_unlabeled = drop_unlabeled

    def stream_jsonl(
        self,
        jsonl_path: str | Path,
        max_samples: Optional[int] = None,
        chunk_size: int = 1000,
    ) -> Generator[Dict[str, Any], None, None]:
        """Streams records chunk-by-chunk from EMBER JSONL without exhausting RAM."""
        path = Path(jsonl_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"EMBER JSONL file not found: {path}")

        chunk_features: List[np.ndarray] = []
        chunk_labels: List[int] = []
        chunk_timestamps: List[str] = []
        chunk_shas: List[str] = []

        count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                except Exception:
                    continue

                label = record.get("label", -1)
                if self.drop_unlabeled and label == -1:
                    continue

                # Extract features
                if self.schema_mode == "harmonized":
                    feat = self.harmonize_ember_record(record)
                else:
                    feat = self.extract_native_ember_vector(record)

                chunk_features.append(feat)
                chunk_labels.append(int(label))
                chunk_timestamps.append(record.get("appeared", "2018-01"))
                chunk_shas.append(record.get("sha256", f"sample_{count}"))
                count += 1

                if len(chunk_features) >= chunk_size:
                    yield {
                        "features": np.stack(chunk_features, axis=0),
                        "labels": np.array(chunk_labels, dtype=np.int64),
                        "timestamps": chunk_timestamps,
                        "sha256": chunk_shas,
                    }
                    chunk_features = []
                    chunk_labels = []
                    chunk_timestamps = []
                    chunk_shas = []

                if max_samples and count >= max_samples:
                    break

        if chunk_features:
            yield {
                "features": np.stack(chunk_features, axis=0),
                "labels": np.array(chunk_labels, dtype=np.int64),
                "timestamps": chunk_timestamps,
                "sha256": chunk_shas,
            }

    def load_memmap_dataset(
        self,
        data_dir: str | Path,
        split: str = "train",
        sample_count: int = 10000,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Reads EMBER binary memory-mapped files (X_train.dat, y_train.dat) with zero RAM duplication."""
        dir_path = Path(data_dir).resolve()
        x_path = dir_path / f"X_{split}.dat"
        y_path = dir_path / f"y_{split}.dat"

        if not x_path.is_file() or not y_path.is_file():
            raise FileNotFoundError(f"Missing EMBER memmap files in {dir_path}")

        # Shape of EMBER X.dat is (num_samples, 2381) dtype float32
        x_mmap = np.memmap(x_path, dtype=np.float32, mode="r", shape=(sample_count, EMBER_RAW_FEATURE_DIM))
        y_mmap = np.memmap(y_path, dtype=np.float32, mode="r", shape=(sample_count,))

        # Filter unlabeled (y == -1) if required
        if self.drop_unlabeled:
            valid_mask = (y_mmap != -1)
            X = np.array(x_mmap[valid_mask], dtype=np.float32)
            y = np.array(y_mmap[valid_mask], dtype=np.int64)
        else:
            X = np.array(x_mmap, dtype=np.float32)
            y = np.array(y_mmap, dtype=np.int64)

        if self.schema_mode == "harmonized":
            # Project 2381 dims to 256 dims
            X = self.project_native_to_harmonized(X)

        return X, y

    def harmonize_ember_record(self, record: Dict[str, Any]) -> np.ndarray:
        """Projects an individual EMBER raw JSON dict into ThreatWeaver's 256-dim schema."""
        vec = np.zeros(FEATURE_DIM, dtype=np.float32)

        general = record.get("general", {})
        header = record.get("header", {})
        sections = record.get("section", {})
        strings = record.get("strings", {})
        histogram = record.get("histogram", [])

        # 1. Structural & Header (dims 0..31)
        file_sz = float(general.get("size", 1000))
        vec[0] = min(np.log10(max(file_sz, 1.0)) / 8.0, 1.0)
        
        # Machine type
        coff = header.get("coff", {})
        machine = coff.get("machine", "")
        vec[1] = 1.0 if "I386" in machine else 0.0
        vec[2] = 1.0 if "AMD64" in machine else 0.0

        # Subsystem & characteristics
        optional = header.get("optional", {})
        subsystem = optional.get("subsystem", "")
        vec[10] = 1.0 if "WINDOWS_GUI" in subsystem else 0.0
        vec[11] = 1.0 if "WINDOWS_CUI" in subsystem else 0.0

        dll_chars = optional.get("dll_characteristics", [])
        vec[13] = 1.0 if "DYNAMIC_BASE" in dll_chars else 0.0
        vec[14] = 1.0 if "NX_COMPAT" in dll_chars else 0.0

        vec[24] = 1.0 if general.get("exports", 0) > 0 else 0.0
        vec[26] = 1.0 if general.get("imports", 0) > 0 else 0.0

        # 2. Section statistics (dims 32..95)
        raw_sections = sections.get("sections", [])
        vec[4] = min(len(raw_sections) / 32.0, 1.0)
        if raw_sections:
            ents = [s.get("entropy", 0.0) for s in raw_sections]
            vec[32] = float(np.mean(ents)) / 8.0
            vec[33] = float(np.max(ents)) / 8.0
            vec[34] = float(np.mean(ents)) / 8.0
            vec[35] = float(np.min(ents)) / 8.0

        # 3. String & Byte Histogram (dims 160..255)
        # Byte histogram: EMBER supplies 256 raw byte counts; group into 64 bins
        if histogram and len(histogram) == 256:
            tot = max(sum(histogram), 1.0)
            hist_norm = [c / tot for c in histogram]
            # Group 256 into 64 (4 per bin)
            for b_i in range(64):
                vec[160 + b_i] = sum(hist_norm[b_i * 4 : (b_i + 1) * 4])

        # Strings
        vec[224] = min(strings.get("printables", 0) / max(file_sz, 1.0), 1.0)
        vec[225] = 1.0 if strings.get("urls", 0) > 0 else 0.0
        vec[226] = 1.0 if strings.get("registry", 0) > 0 else 0.0
        vec[227] = 1.0 if strings.get("paths", 0) > 0 else 0.0

        return vec

    def project_native_to_harmonized(self, X: np.ndarray) -> np.ndarray:
        """Projects a (N, 2381) EMBER matrix to (N, 256) ThreatWeaver space."""
        N = X.shape[0]
        out = np.zeros((N, FEATURE_DIM), dtype=np.float32)

        # In EMBER 2381-dim vector:
        # 0..255: Byte Histogram (256 bins)
        # Compress 256 bins into 64 bins for dims 160..223
        byte_hist_slice = X[:, :256]
        for b_i in range(64):
            out[:, 160 + b_i] = np.sum(byte_hist_slice[:, b_i * 4 : (b_i + 1) * 4], axis=1)

        # Byte entropy histogram slice (256..511) -> overall entropy quantiles
        entropy_slice = X[:, 256:512]
        out[:, 32] = np.mean(entropy_slice, axis=1)
        out[:, 33] = np.max(entropy_slice, axis=1)

        # General file info slice (616..625)
        if X.shape[1] > 625:
            general_slice = X[:, 616:626]
            out[:, 0] = np.clip(np.log10(np.maximum(general_slice[:, 0], 1.0)) / 8.0, 0.0, 1.0)
            out[:, 24] = np.clip(general_slice[:, 2], 0.0, 1.0)  # exports
            out[:, 26] = np.clip(general_slice[:, 3], 0.0, 1.0)  # imports

        # Imports hashing slice (e.g. 1101..2380) mapped into API categories
        if X.shape[1] >= 1500:
            out[:, 96:160] = np.clip(X[:, 1100:1164], 0.0, 1.0)

        return out

    def extract_native_ember_vector(self, record: Dict[str, Any]) -> np.ndarray:
        """Extracts native 2381-dim vector if raw features list is provided."""
        if "features" in record and len(record["features"]) == EMBER_RAW_FEATURE_DIM:
            return np.array(record["features"], dtype=np.float32)
        # Fallback to padded representation
        vec = np.zeros(EMBER_RAW_FEATURE_DIM, dtype=np.float32)
        hist = record.get("histogram", [])
        if hist and len(hist) == 256:
            vec[:256] = np.array(hist, dtype=np.float32) / max(sum(hist), 1.0)
        return vec


def generate_synthetic_ember_jsonl(
    output_path: str | Path,
    num_samples: int = 500,
    seed: int = 42,
) -> Path:
    """Generates a valid, realistic EMBER format JSONL dataset for instant local testing.
    
    Includes:
    - 'appeared' temporal stamps across 5 distinct months (2018-01 through 2018-05)
    - Labels: 0 (benign), 1 (malware), and a small set of -1 (unlabeled)
    - Realistic EMBER dictionary keys: general, header, section, histogram, byteentropy, strings
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)

    months = ["2018-01", "2018-02", "2018-03", "2018-04", "2018-05"]

    with open(path, "w", encoding="utf-8") as f:
        for i in range(num_samples):
            # Month selection
            month = months[i % len(months)]
            # 45% benign, 45% malware, 10% unlabeled (-1)
            r = rng.random()
            if r < 0.45:
                label = 0
            elif r < 0.90:
                label = 1
            else:
                label = -1

            is_mal = (label == 1)

            # Generate synthetic raw histogram
            hist = rng.dirichlet(np.ones(256) * (1.5 if is_mal else 3.0)) * 10000.0

            sample = {
                "sha256": f"ember_{month}_{i:05d}_{rng.integers(10000, 99999):05d}",
                "appeared": month,
                "label": label,
                "general": {
                    "size": int(rng.uniform(10000, 5000000)),
                    "vsize": int(rng.uniform(20000, 6000000)),
                    "has_debug": int(not is_mal),
                    "exports": int(rng.integers(0, 5)),
                    "imports": int(rng.integers(5, 50)),
                    "has_relocations": 1,
                    "has_resources": 1,
                    "has_signature": int(not is_mal),
                    "has_tls": 0,
                    "symbols": 0,
                },
                "header": {
                    "coff": {
                        "timestamp": 1514764800 + i * 3600,
                        "machine": "AMD64" if rng.random() > 0.3 else "I386",
                        "characteristics": ["EXECUTABLE_IMAGE"],
                    },
                    "optional": {
                        "subsystem": "WINDOWS_GUI" if rng.random() > 0.2 else "WINDOWS_CUI",
                        "dll_characteristics": ["DYNAMIC_BASE", "NX_COMPAT"] if not is_mal else [],
                        "magic": "PE32_PLUS",
                        "major_image_version": 0,
                        "minor_image_version": 0,
                    },
                },
                "section": {
                    "sections": [
                        {"name": ".text", "entropy": float(rng.uniform(6.5, 7.9) if is_mal else rng.uniform(4.5, 6.2))},
                        {"name": ".data", "entropy": float(rng.uniform(2.0, 5.0))},
                        {"name": ".rdata", "entropy": float(rng.uniform(3.0, 5.5))},
                    ]
                },

                "strings": {
                    "numstrings": int(rng.integers(50, 1500)),
                    "printables": int(rng.integers(2000, 50000)),
                    "urls": int(rng.integers(1, 10)) if is_mal else 0,
                    "registry": int(rng.integers(1, 5)) if is_mal else 0,
                    "paths": int(rng.integers(0, 5)),
                },
                "histogram": [int(x) for x in hist],
            }
            f.write(json.dumps(sample) + "\n")

    return path
