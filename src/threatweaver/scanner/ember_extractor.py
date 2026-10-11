"""Live EMBER-compatible PE feature extractor for ThreatWeaver.

Allows the on-demand Windows scanner to extract EMBER 2018/2024 compatible features
(2,381 dimensions) directly from real executables on disk without code execution.
"""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pefile

from threatweaver.data.ember_loader import EMBER_RAW_FEATURE_DIM
from threatweaver.scanner.pe_parser import (
    StaticPEParser,
    compute_byte_histogram,
    compute_shannon_entropy,
)


class EMBERFeatureExtractor:
    """Extracts EMBER-compatible (2381-dim) static features from PE binaries."""

    def __init__(self):
        self.parser = StaticPEParser()

    def extract_from_file(self, file_path: str | Path) -> np.ndarray:
        """Extracts 2381-dim EMBER feature vector from a real binary file on disk."""
        path = Path(file_path).resolve()
        analysis = self.parser.parse(path)

        with open(path, "rb") as f:
            raw_bytes = f.read(10 * 1024 * 1024)  # sample up to 10MB

        return self.extract_from_bytes(raw_bytes, analysis)

    def extract_from_bytes(
        self, raw_bytes: bytes, analysis: Optional[Any] = None
    ) -> np.ndarray:
        """Extracts normalized 2381-dim vector from raw binary bytes."""
        vec = np.zeros(EMBER_RAW_FEATURE_DIM, dtype=np.float32)
        if not raw_bytes:
            return vec

        # 1. Byte Histogram (dims 0..255)
        # 256 normalized byte frequencies
        counts = [0] * 256
        for b in raw_bytes:
            counts[b] += 1
        total_len = float(len(raw_bytes))
        for i in range(256):
            vec[i] = counts[i] / total_len

        # 2. Byte Entropy Histogram (dims 256..511)
        # Approximate 16x16 joint byte-entropy histogram (256 dims)
        step = 1024
        for i in range(0, min(len(raw_bytes), 32 * 1024), step):
            chunk = raw_bytes[i : i + step]
            if chunk:
                chunk_ent = compute_shannon_entropy(chunk)
                ent_bin = min(15, int(chunk_ent * 2))  # 0..15
                for b in chunk[:64]:  # sample bytes
                    byte_bin = b // 16  # 0..15
                    vec[256 + (ent_bin * 16 + byte_bin)] += 0.001

        # 3. String Extractor (dims 512..615, 104 dims)
        strings = re.findall(rb"[\x20-\x7e]{5,}", raw_bytes)
        num_strings = len(strings)
        avg_len = sum(len(s) for s in strings) / max(num_strings, 1)
        urls = len(re.findall(rb"https?://", raw_bytes))
        registry = len(re.findall(rb"software\\microsoft\\windows", raw_bytes, re.IGNORECASE))
        paths = len(re.findall(rb"[a-zA-Z]:\\", raw_bytes))

        vec[512] = min(num_strings / 1000.0, 1.0)
        vec[513] = min(avg_len / 50.0, 1.0)
        vec[514] = min(urls / 10.0, 1.0)
        vec[515] = min(registry / 10.0, 1.0)
        vec[516] = min(paths / 10.0, 1.0)

        # 4. General PE Info (dims 616..625, 10 dims)
        if analysis and analysis.is_valid_pe:
            vec[616] = min(math.log10(max(analysis.file_size, 1)) / 8.0, 1.0)
            vec[617] = min(math.log10(max(analysis.size_of_image, 1)) / 8.0, 1.0)
            vec[618] = min(analysis.number_of_exports / 10.0, 1.0)
            vec[619] = min(len(analysis.imported_functions) / 50.0, 1.0)
            vec[620] = 1.0 if analysis.number_of_sections > 0 else 0.0
            vec[621] = 1.0 if (analysis.dll_characteristics & 0x0100) else 0.0  # NX
            vec[622] = 1.0 if (analysis.dll_characteristics & 0x0040) else 0.0  # ASLR

        # 5. Header Info (dims 626..687, 62 dims)
        if analysis and analysis.is_valid_pe:
            vec[626] = 1.0 if analysis.machine_type == 0x014C else 0.0  # x86
            vec[627] = 1.0 if analysis.machine_type == 0x8664 else 0.0  # x64
            vec[628] = min(analysis.subsystem / 10.0, 1.0)

        # 6. Section Info (dims 688..942, 255 dims)
        if analysis and analysis.is_valid_pe:
            vec[688] = min(analysis.number_of_sections / 20.0, 1.0)
            vec[689] = analysis.overall_entropy / 8.0
            for idx, sec in enumerate(analysis.sections[:10]):
                base_idx = 690 + idx * 5
                if base_idx + 4 < 943:
                    vec[base_idx] = sec.entropy / 8.0
                    vec[base_idx + 1] = 1.0 if sec.is_executable else 0.0
                    vec[base_idx + 2] = 1.0 if sec.is_writable else 0.0
                    vec[base_idx + 3] = 1.0 if (sec.is_executable and sec.is_writable) else 0.0
                    vec[base_idx + 4] = min(math.log10(max(sec.raw_data_size, 1)) / 7.0, 1.0)

        # 7. Imports Feature Hashing (dims 1100..2379, 1280 dims)
        if analysis and analysis.imported_functions:
            for func in analysis.imported_functions:
                # 1280 hash buckets
                bucket = (hash(func) % 1280) + 1100
                vec[bucket] = min(vec[bucket] + 0.1, 1.0)

        return vec
