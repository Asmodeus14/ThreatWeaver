"""Feature extraction engine for ThreatWeaver.

Translates static PE analysis and raw byte structures into a versioned,
fixed-dimensional numeric representation (Schema v1.0, 256 dimensions)
without ever executing untrusted binaries.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from threatweaver.scanner.pe_parser import (
    PEAnalysisResult,
    StaticPEParser,
    compute_byte_histogram,
    compute_shannon_entropy,
)

SCHEMA_VERSION = "1.0"
FEATURE_DIM = 256

# High-signal suspicious API patterns
SUSPICIOUS_APIS = {
    "injection": [
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntunmapviewofsection", "queueuserapc", "setthreadcontext",
        "virtualprotectex", "rtlmovememory", "zwunmapviewofsection"
    ],
    "dynamic_load": [
        "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
        "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress"
    ],
    "evasion": [
        "isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstringa",
        "outputdebugstringw", "ntqueryinformationprocess", "gettickcount",
        "timegettime", "findwindowa", "findwindoww"
    ],
    "persistence": [
        "regsetvalueexa", "regsetvalueexw", "regcreatekeya", "regcreatekeyw",
        "createservicea", "createservicew", "openscmanagera", "openscmanagerw"
    ],
    "hooking": [
        "setwindowshookexa", "setwindowshookexw", "getasynckeystate",
        "getkeystate", "registerhotkey", "callnexthookex"
    ],
    "network": [
        "internetopena", "internetopenw", "httpopenrequesta", "httpopenrequestw",
        "urldownloadtofilea", "urldownloadtofilew", "wsastartup", "connect", "send", "recv"
    ],
    "process_exec": [
        "winexec", "shellexecutea", "shellexecutew", "createprocessa",
        "createprocessw", "system"
    ],
    "crypto": [
        "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptacquirecontexta",
        "cryptacquirecontextw", "bcryptencrypt", "bcryptdecrypt"
    ],
}

SUSPICIOUS_STRING_REGEXES = {
    "powershell": re.compile(rb"powershell|bypass|-enc|-encodedcommand", re.IGNORECASE),
    "cmd": re.compile(rb"cmd\.exe|\/c\s+start", re.IGNORECASE),
    "url": re.compile(rb"https?:\/\/[a-zA-Z0-9\.\-\/]+", re.IGNORECASE),
    "ip": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "reg_run": re.compile(rb"software\\microsoft\\windows\\currentversion\\run", re.IGNORECASE),
    "vbs_wscript": re.compile(rb"wscript\.shell|cscript\.exe", re.IGNORECASE),
    "base64_marker": re.compile(rb"tvqqaam|uexpbg|aaoaae", re.IGNORECASE),  # common PE base64 prefixes
    "tor_onion": re.compile(rb"\.onion\b", re.IGNORECASE),
}


@dataclass
class ExtractedFeatures:
    """Standardized extracted static feature representation."""
    schema_version: str
    feature_vector: np.ndarray  # Shape: (256,), dtype float32
    raw_metadata: Dict[str, Any]
    detected_indicators: List[str]
    is_valid_pe: bool
    sha256: str
    file_size: int


class FeatureExtractor:
    """Deterministic, hardened static feature extractor for PE files."""

    def __init__(self, schema_version: str = SCHEMA_VERSION):
        self.schema_version = schema_version
        self.parser = StaticPEParser()

    def extract_from_file(self, file_path: str | Path) -> ExtractedFeatures:
        """Extracts 256-dim feature vector from given file path."""
        path = Path(file_path).resolve()
        analysis = self.parser.parse(path)

        # Read small sample of bytes for string/byte statistical analysis
        raw_bytes = b""
        try:
            with open(path, "rb") as f:
                raw_bytes = f.read(10 * 1024 * 1024)  # sample first 10MB max
        except Exception:
            pass

        return self.extract_from_pe_analysis(analysis, raw_bytes)

    def extract_from_pe_analysis(
        self, analysis: PEAnalysisResult, raw_bytes: bytes = b""
    ) -> ExtractedFeatures:
        """Constructs 256-dimensional vector from PE analysis result and raw bytes."""
        vec = np.zeros(FEATURE_DIM, dtype=np.float32)
        indicators: List[str] = list(analysis.anomalies)

        if not analysis.is_valid_pe:
            # Return zeroed vector with invalid indicator
            return ExtractedFeatures(
                schema_version=self.schema_version,
                feature_vector=vec,
                raw_metadata={"error": analysis.error_message, "is_valid": False},
                detected_indicators=indicators,
                is_valid_pe=False,
                sha256=analysis.sha256,
                file_size=analysis.file_size,
            )

        # ==========================================
        # 1. Structural & Header Features (dims 0..31)
        # ==========================================
        file_sz = float(analysis.file_size)
        vec[0] = min(math.log10(max(file_sz, 1.0)) / 8.0, 1.0)
        vec[1] = 1.0 if analysis.machine_type == 0x014C else 0.0  # x86
        vec[2] = 1.0 if analysis.machine_type == 0x8664 else 0.0  # x64
        vec[3] = 1.0 if analysis.machine_type not in (0x014C, 0x8664) else 0.0
        vec[4] = min(analysis.number_of_sections / 32.0, 1.0)

        # Timestamp anomaly (e.g. 0 or > current year + 2)
        current_epoch = time.time()
        is_bad_time = (analysis.timestamp == 0) or (analysis.timestamp > current_epoch + 86400 * 365 * 2)
        vec[5] = 1.0 if is_bad_time else 0.0
        if is_bad_time:
            indicators.append("Anomalous or zeroed PE compilation timestamp")

        chars = analysis.characteristics
        vec[6] = 1.0 if (chars & 0x0002) else 0.0  # IMAGE_FILE_EXECUTABLE_IMAGE
        vec[7] = 1.0 if (chars & 0x2000) else 0.0  # IMAGE_FILE_DLL
        vec[8] = 1.0 if (chars & 0x0100) else 0.0  # 32-bit word machine
        vec[9] = 1.0 if (chars & 0x0020) else 0.0  # Large address aware

        subsys = analysis.subsystem
        vec[10] = 1.0 if subsys == 2 else 0.0  # GUI
        vec[11] = 1.0 if subsys == 3 else 0.0  # Console
        vec[12] = 1.0 if subsys == 1 else 0.0  # Native driver

        dll_c = analysis.dll_characteristics
        vec[13] = 1.0 if (dll_c & 0x0040) else 0.0  # ASLR (DYNAMIC_BASE)
        vec[14] = 1.0 if (dll_c & 0x0100) else 0.0  # DEP/NX (NX_COMPAT)
        vec[15] = 1.0 if (dll_c & 0x0400) else 0.0  # NO_SEH
        vec[16] = 1.0 if (dll_c & 0x0020) else 0.0  # HIGH_ENTROPY_VA

        # Missing DEP or ASLR in modern binary is notable
        if not (dll_c & 0x0100):
            indicators.append("DEP/NX compatibility disabled in PE header")
        if not (dll_c & 0x0040):
            indicators.append("ASLR (Dynamic Base) disabled in PE header")

        vec[17] = min(math.log10(max(analysis.size_of_image, 1)) / 8.0, 1.0)
        vec[18] = min(math.log10(max(analysis.size_of_headers, 1)) / 5.0, 1.0)
        vec[19] = min(math.log10(max(analysis.size_of_code, 1)) / 8.0, 1.0)
        vec[20] = min(math.log10(max(analysis.size_of_initialized_data, 1)) / 8.0, 1.0)

        soi = max(analysis.size_of_image, 1)
        vec[21] = min(float(analysis.entry_point_rva) / float(soi), 1.0)
        vec[22] = 1.0 if any("outside all defined sections" in a for a in analysis.anomalies) else 0.0
        vec[23] = 1.0 if any("non-executable section" in a for a in analysis.anomalies) else 0.0

        vec[24] = 1.0 if analysis.number_of_exports > 0 else 0.0
        vec[25] = min(math.log10(max(analysis.number_of_exports, 0) + 1) / 4.0, 1.0)
        vec[26] = 1.0 if analysis.imported_dlls else 0.0
        vec[27] = min(math.log10(len(analysis.imported_dlls) + 1) / 3.0, 1.0)
        vec[28] = min(math.log10(len(analysis.imported_functions) + 1) / 4.0, 1.0)
        vec[29] = 1.0 if analysis.imphash else 0.0
        vec[30] = min(len(analysis.anomalies) / 10.0, 1.0)
        vec[31] = 0.0

        # ==========================================
        # 2. Section-Level Statistics (dims 32..95)
        # ==========================================
        entropies = [sec.entropy for sec in analysis.sections] if analysis.sections else [0.0]
        max_ent = max(entropies)
        mean_ent = sum(entropies) / len(entropies)
        min_ent = min(entropies)

        vec[32] = analysis.overall_entropy / 8.0
        vec[33] = max_ent / 8.0
        vec[34] = mean_ent / 8.0
        vec[35] = min_ent / 8.0

        n_exec = sum(1 for s in analysis.sections if s.is_executable)
        n_write = sum(1 for s in analysis.sections if s.is_writable)
        n_wx = sum(1 for s in analysis.sections if s.is_executable and s.is_writable)
        n_zero_raw = sum(1 for s in analysis.sections if s.raw_data_size == 0)
        n_high_ent = sum(1 for s in analysis.sections if s.entropy > 7.0)

        vec[36] = min(n_exec / 10.0, 1.0)
        vec[37] = min(n_write / 10.0, 1.0)
        vec[38] = min(n_wx / 5.0, 1.0)
        vec[39] = min(n_zero_raw / 5.0, 1.0)
        vec[40] = min(n_high_ent / 5.0, 1.0)

        tot_virt = sum(s.virtual_size for s in analysis.sections)
        tot_raw = sum(s.raw_data_size for s in analysis.sections)
        v_to_r = (tot_virt / max(tot_raw, 1)) if tot_raw > 0 else 0.0
        vec[41] = min(v_to_r / 10.0, 1.0)

        # Standard section metrics (.text, .data, .rdata, .rsrc, .reloc)
        std_secs = [".text", ".data", ".rdata", ".rsrc", ".reloc"]
        sec_dict = {s.name.lower(): s for s in analysis.sections}
        dim_idx = 42
        for std in std_secs:
            if std in sec_dict:
                s = sec_dict[std]
                vec[dim_idx] = 1.0
                vec[dim_idx + 1] = s.entropy / 8.0
                vec[dim_idx + 2] = min(float(s.raw_data_size) / max(file_sz, 1.0), 1.0)
            else:
                vec[dim_idx] = 0.0
                vec[dim_idx + 1] = 0.0
                vec[dim_idx + 2] = 0.0
            dim_idx += 3  # 15 dims consumed (42..56)

        # Top 16 section entropies (padded)
        sorted_entropies = sorted(entropies, reverse=True)[:16]
        for i in range(16):
            if i < len(sorted_entropies):
                vec[57 + i] = sorted_entropies[i] / 8.0
            else:
                vec[57 + i] = 0.0  # dims 57..72

        # Top 16 raw-to-virtual ratios (padded)
        ratios = [min(float(s.virtual_size) / max(s.raw_data_size, 1), 10.0) / 10.0 for s in analysis.sections][:16]
        for i in range(16):
            if i < len(ratios):
                vec[73 + i] = ratios[i]
            else:
                vec[73 + i] = 0.0  # dims 73..88

        # 7 reserved dims (89..95) are 0.0

        # ==========================================
        # 3. Import / API Categorization (dims 96..159)
        # ==========================================
        imported_funcs_lower = {f.lower() for f in analysis.imported_functions}
        cat_counts: Dict[str, int] = {}
        idx = 96
        for cat_name, api_list in SUSPICIOUS_APIS.items():
            matches = [api for api in api_list if any(api in f for f in imported_funcs_lower)]
            count = len(matches)
            cat_counts[cat_name] = count
            vec[idx] = 1.0 if count > 0 else 0.0
            vec[idx + 1] = min(math.log10(count + 1) / 2.0, 1.0)
            idx += 2
            if count > 0:
                indicators.append(f"Imports APIs related to {cat_name}: {', '.join(matches[:4])}")

        # Hash projection of DLL names and imported symbols into remaining 48 dims (112..159)
        for dll in analysis.imported_dlls:
            bucket = (hash(dll) % 24) + 112
            vec[bucket] = min(vec[bucket] + 0.2, 1.0)
        for func in analysis.imported_functions:
            bucket = (hash(func) % 24) + 136
            vec[bucket] = min(vec[bucket] + 0.1, 1.0)

        # ====================================================
        # 4. Byte Histogram & String Indicators (dims 160..255)
        # ====================================================
        # 64 dims for compressed byte histogram (160..223)
        if analysis.byte_histogram and len(analysis.byte_histogram) == 64:
            vec[160:224] = np.array(analysis.byte_histogram, dtype=np.float32)

        # String and content analysis from raw_bytes
        if raw_bytes:
            # Printable ASCII ratio
            printable = sum(1 for b in raw_bytes if 32 <= b <= 126 or b in (9, 10, 13))
            ascii_ratio = printable / max(len(raw_bytes), 1)
            vec[224] = ascii_ratio

            # Search for suspicious string indicators (dims 225..232)
            s_idx = 225
            for str_name, regex in SUSPICIOUS_STRING_REGEXES.items():
                if regex.search(raw_bytes):
                    vec[s_idx] = 1.0
                    indicators.append(f"Detected suspicious string pattern: {str_name}")
                s_idx += 1

            # Quantiles of 1KB sliding window entropy (dims 233..240)
            chunk_size = 1024
            chunk_entropies = []
            for i in range(0, min(len(raw_bytes), 64 * 1024), chunk_size):
                chunk = raw_bytes[i : i + chunk_size]
                if chunk:
                    chunk_entropies.append(compute_shannon_entropy(chunk))
            
            if chunk_entropies:
                quantiles = np.quantile(chunk_entropies, [0.0, 0.25, 0.5, 0.75, 0.9, 1.0])
                for qi, val in enumerate(quantiles):
                    vec[233 + qi] = val / 8.0

        metadata = {
            "sha256": analysis.sha256,
            "imphash": analysis.imphash,
            "file_size": analysis.file_size,
            "machine": analysis.machine_name,
            "subsystem": analysis.subsystem_name,
            "num_sections": analysis.number_of_sections,
            "num_imported_dlls": len(analysis.imported_dlls),
            "num_imported_functions": len(analysis.imported_functions),
            "overall_entropy": analysis.overall_entropy,
            "api_category_hits": cat_counts,
        }

        return ExtractedFeatures(
            schema_version=self.schema_version,
            feature_vector=vec,
            raw_metadata=metadata,
            detected_indicators=indicators,
            is_valid_pe=True,
            sha256=analysis.sha256,
            file_size=analysis.file_size,
        )
