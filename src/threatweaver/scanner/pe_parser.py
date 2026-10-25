"""Hardened, static PE parser for ThreatWeaver.

Safely inspects untrusted Windows Portable Executable (PE) files without execution.
Guarantees bounded resource usage, structural validation, and robust error handling.
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pefile

# Limits for resource boundedness and defensive parsing
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
MIN_PE_SIZE = 256  # Smallest conceivable valid PE header footprint
MAX_SECTIONS_PARSE = 96
MAX_IMPORTS_PARSE = 2048


class PEValidationError(Exception):
    """Raised when file fails basic PE structural validation."""


class FileTooLargeError(PEValidationError):
    """Raised when file exceeds configured safe size limit."""


class InvalidPEMagicError(PEValidationError):
    """Raised when file is not a valid PE binary."""


class CorruptPEStructureError(PEValidationError):
    """Raised when PE structure is corrupted or truncated."""


@dataclass(frozen=True)
class SectionInfo:
    """Summary of an individual PE section."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_data_size: int
    entropy: float
    is_readable: bool
    is_writable: bool
    is_executable: bool
    characteristics: int


@dataclass
class PEAnalysisResult:
    """Structured static analysis metadata from a PE binary."""
    file_path: str
    file_size: int
    sha256: str
    md5: str
    imphash: Optional[str]
    is_valid_pe: bool
    machine_type: int
    machine_name: str
    subsystem: int
    subsystem_name: str
    timestamp: int
    characteristics: int
    dll_characteristics: int
    entry_point_rva: int
    image_base: int
    size_of_image: int
    size_of_headers: int
    size_of_code: int
    size_of_initialized_data: int
    number_of_sections: int
    sections: List[SectionInfo] = field(default_factory=list)
    imported_dlls: List[str] = field(default_factory=list)
    imported_functions: List[str] = field(default_factory=list)
    number_of_exports: int = 0
    overall_entropy: float = 0.0
    byte_histogram: List[float] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


import numpy as np

def compute_shannon_entropy(data: bytes) -> float:
    """Computes Shannon entropy (0.0 - 8.0 bits per byte) via fast C/NumPy bincount."""
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    non_zero = counts[counts > 0]
    p = non_zero / float(len(data))
    return float(-np.sum(p * np.log2(p)))


def compute_byte_histogram(data: bytes, num_bins: int = 64) -> List[float]:
    """Generates a compressed, L1-normalized byte histogram via vectorized NumPy grouping."""
    if not data:
        return [0.0] * num_bins
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    step = 256 // num_bins
    grouped = counts.reshape(num_bins, step).sum(axis=1)
    return (grouped / float(len(data))).tolist()


class StaticPEParser:
    """Static PE file parser with strict security boundaries and resource bounds."""

    def __init__(self, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
        self.max_file_size = max_file_size

    def validate_file_pre_parse(self, path: Path) -> int:
        """Performs initial non-executing validation of file size and magic bytes."""
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        file_size = path.stat().st_size
        if file_size > self.max_file_size:
            raise FileTooLargeError(
                f"File size ({file_size} bytes) exceeds limit ({self.max_file_size} bytes)"
            )
        if file_size < MIN_PE_SIZE:
            raise InvalidPEMagicError(
                f"File size ({file_size} bytes) is too small to be a valid PE"
            )

        # Quick check for MZ magic (0x5A4D)
        with open(path, "rb") as f:
            magic = f.read(2)
            if magic != b"MZ":
                raise InvalidPEMagicError("Missing MZ magic signature at offset 0")

            # Check PE header offset at 0x3C (e_lfanew)
            f.seek(0x3C)
            lfanew_bytes = f.read(4)
            if len(lfanew_bytes) < 4:
                raise CorruptPEStructureError("File truncated before e_lfanew offset")
            
            pe_offset = struct.unpack("<I", lfanew_bytes)[0]
            if pe_offset < 0x40 or pe_offset > file_size - 4:
                raise CorruptPEStructureError(f"Invalid e_lfanew PE header offset: {pe_offset}")

            # Check PE signature at pe_offset
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                raise InvalidPEMagicError(f"Missing PE\\0\\0 signature at offset {pe_offset}")

        return file_size

    def parse(
        self, file_path: str | Path, raw_data: Optional[bytes] = None
    ) -> PEAnalysisResult:
        """Parses a PE file and extracts structural metadata without execution."""
        path = Path(file_path).resolve()
        anomalies: List[str] = []

        # Validate structure before full parse
        try:
            file_size = self.validate_file_pre_parse(path)
        except PEValidationError as e:
            # Return structured result indicating invalid / unsupported format
            sha256 = self._compute_hash(path) if path.is_file() else "UNKNOWN"
            return PEAnalysisResult(
                file_path=str(path),
                file_size=path.stat().st_size if path.is_file() else 0,
                sha256=sha256,
                md5="",
                imphash=None,
                is_valid_pe=False,
                machine_type=0,
                machine_name="Unknown",
                subsystem=0,
                subsystem_name="Unknown",
                timestamp=0,
                characteristics=0,
                dll_characteristics=0,
                entry_point_rva=0,
                image_base=0,
                size_of_image=0,
                size_of_headers=0,
                size_of_code=0,
                size_of_initialized_data=0,
                number_of_sections=0,
                anomalies=[f"Validation failed: {str(e)}"],
                error_message=str(e),
            )

        if raw_data is not None:
            file_bytes = raw_data[: self.max_file_size]
        else:
            with open(path, "rb") as f:
                file_bytes = f.read(self.max_file_size)

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        md5 = hashlib.md5(file_bytes).hexdigest()
        overall_entropy = compute_shannon_entropy(file_bytes)
        byte_hist = compute_byte_histogram(file_bytes, num_bins=64)

        try:
            # Use fast_load=True and explicitly parse directories safely
            pe = pefile.PE(data=file_bytes, fast_load=True)
        except Exception as e:
            return PEAnalysisResult(
                file_path=str(path),
                file_size=file_size,
                sha256=sha256,
                md5=md5,
                imphash=None,
                is_valid_pe=False,
                machine_type=0,
                machine_name="Corrupt",
                subsystem=0,
                subsystem_name="Corrupt",
                timestamp=0,
                characteristics=0,
                dll_characteristics=0,
                entry_point_rva=0,
                image_base=0,
                size_of_image=0,
                size_of_headers=0,
                size_of_code=0,
                size_of_initialized_data=0,
                number_of_sections=0,
                overall_entropy=overall_entropy,
                byte_histogram=byte_hist,
                anomalies=[f"PE structure corruption: {str(e)}"],
                error_message=str(e),
            )

        try:
            # File Header values
            file_header = pe.FILE_HEADER
            machine_type = getattr(file_header, "Machine", 0)
            machine_name = pefile.MACHINE_TYPE.get(machine_type, f"0x{machine_type:04X}")
            timestamp = getattr(file_header, "TimeDateStamp", 0)
            characteristics = getattr(file_header, "Characteristics", 0)
            num_sections = getattr(file_header, "NumberOfSections", 0)

            # Optional Header values
            opt_header = getattr(pe, "OPTIONAL_HEADER", None)
            if opt_header:
                subsystem = getattr(opt_header, "Subsystem", 0)
                subsystem_name = pefile.SUBSYSTEM_TYPE.get(subsystem, f"0x{subsystem:04X}")
                dll_characteristics = getattr(opt_header, "DllCharacteristics", 0)
                entry_point = getattr(opt_header, "AddressOfEntryPoint", 0)
                image_base = getattr(opt_header, "ImageBase", 0)
                size_of_image = getattr(opt_header, "SizeOfImage", 0)
                size_of_headers = getattr(opt_header, "SizeOfHeaders", 0)
                size_of_code = getattr(opt_header, "SizeOfCode", 0)
                size_of_init_data = getattr(opt_header, "SizeOfInitializedData", 0)
            else:
                subsystem = 0
                subsystem_name = "None"
                dll_characteristics = 0
                entry_point = 0
                image_base = 0
                size_of_image = 0
                size_of_headers = 0
                size_of_code = 0
                size_of_init_data = 0

            # Parse sections safely
            parsed_sections: List[SectionInfo] = []
            sections_list = getattr(pe, "sections", [])[:MAX_SECTIONS_PARSE]
            for sec in sections_list:
                sec_name = sec.Name.decode("latin1", errors="replace").strip("\x00")
                sec_va = getattr(sec, "VirtualAddress", 0)
                sec_vs = getattr(sec, "Misc_VirtualSize", 0)
                sec_raw_size = getattr(sec, "SizeOfRawData", 0)
                sec_chars = getattr(sec, "Characteristics", 0)

                # Entropy calculation on raw section data
                try:
                    sec_data = sec.get_data()
                    sec_entropy = compute_shannon_entropy(sec_data) if sec_data else 0.0
                except Exception:
                    sec_entropy = 0.0

                is_read = bool(sec_chars & 0x40000000)
                is_write = bool(sec_chars & 0x80000000)
                is_exec = bool(sec_chars & 0x20000000)

                # Flag suspicious section anomalies
                if is_write and is_exec:
                    anomalies.append(f"Section {sec_name} is both writable and executable (W^X violation)")
                if sec_entropy > 7.2:
                    anomalies.append(f"Section {sec_name} has high entropy ({sec_entropy:.2f}), possible packing/encryption")
                if sec_raw_size == 0 and sec_vs > 0x1000:
                    anomalies.append(f"Section {sec_name} has zero raw size but non-zero virtual size (potential unpack target)")

                parsed_sections.append(
                    SectionInfo(
                        name=sec_name,
                        virtual_address=sec_va,
                        virtual_size=sec_vs,
                        raw_data_size=sec_raw_size,
                        entropy=sec_entropy,
                        is_readable=is_read,
                        is_writable=is_write,
                        is_executable=is_exec,
                        characteristics=sec_chars,
                    )
                )

            # Check entry point location
            if entry_point > 0 and parsed_sections:
                ep_found = False
                for sec in parsed_sections:
                    if sec.virtual_address <= entry_point < (sec.virtual_address + max(sec.virtual_size, sec.raw_data_size)):
                        ep_found = True
                        if not sec.is_executable:
                            anomalies.append(f"Entry point {entry_point:#x} is inside non-executable section {sec.name}")
                        break
                if not ep_found:
                    anomalies.append(f"Entry point {entry_point:#x} lies outside all defined sections")

            # Parse Import Directory safely
            imported_dlls: List[str] = []
            imported_funcs: List[str] = []
            imphash: Optional[str] = None
            try:
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                ])
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode("latin1", errors="replace").lower()
                        imported_dlls.append(dll_name)
                        for imp in entry.imports:
                            if len(imported_funcs) >= MAX_IMPORTS_PARSE:
                                break
                            if imp.name:
                                func_name = imp.name.decode("latin1", errors="replace")
                                imported_funcs.append(func_name)
                            elif imp.ordinal:
                                imported_funcs.append(f"{dll_name}#ord{imp.ordinal}")

                # Safely attempt imphash
                try:
                    imphash = pe.get_imphash()
                except Exception:
                    imphash = None

            except Exception as e:
                anomalies.append(f"Import parsing warning: {str(e)}")

            # Parse Export count safely
            num_exports = 0
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and hasattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols"):
                num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

            pe.close()

            return PEAnalysisResult(
                file_path=str(path),
                file_size=file_size,
                sha256=sha256,
                md5=md5,
                imphash=imphash,
                is_valid_pe=True,
                machine_type=machine_type,
                machine_name=machine_name,
                subsystem=subsystem,
                subsystem_name=subsystem_name,
                timestamp=timestamp,
                characteristics=characteristics,
                dll_characteristics=dll_characteristics,
                entry_point_rva=entry_point,
                image_base=image_base,
                size_of_image=size_of_image,
                size_of_headers=size_of_headers,
                size_of_code=size_of_code,
                size_of_initialized_data=size_of_init_data,
                number_of_sections=num_sections,
                sections=parsed_sections,
                imported_dlls=imported_dlls,
                imported_functions=imported_funcs,
                number_of_exports=num_exports,
                overall_entropy=overall_entropy,
                byte_histogram=byte_hist,
                anomalies=anomalies,
                error_message=None,
            )

        except Exception as e:
            try:
                pe.close()
            except Exception:
                pass
            return PEAnalysisResult(
                file_path=str(path),
                file_size=file_size,
                sha256=sha256,
                md5=md5,
                imphash=None,
                is_valid_pe=False,
                machine_type=0,
                machine_name="Error",
                subsystem=0,
                subsystem_name="Error",
                timestamp=0,
                characteristics=0,
                dll_characteristics=0,
                entry_point_rva=0,
                image_base=0,
                size_of_image=0,
                size_of_headers=0,
                size_of_code=0,
                size_of_initialized_data=0,
                number_of_sections=0,
                overall_entropy=overall_entropy,
                byte_histogram=byte_hist,
                anomalies=[f"Extraction exception: {str(e)}"],
                error_message=str(e),
            )

    def _compute_hash(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
