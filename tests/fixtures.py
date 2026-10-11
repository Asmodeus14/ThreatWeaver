"""Test fixtures and synthetic PE generator for ThreatWeaver.

Generates structurally valid and controlled test binaries without executing any code.
"""

import os
import struct
from pathlib import Path


def create_minimal_pe(
    target_path: Path,
    is_64bit: bool = True,
    section_name: str = ".text",
    raw_section_data: bytes = b"\x90" * 512,  # harmless NOPs
    writable_and_executable: bool = False,
    is_dll: bool = False,
) -> Path:
    """Generates a minimal, syntactically valid PE file for benign static analysis testing."""
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # DOS Header (64 bytes)
    # Magic 'MZ' at 0, e_lfanew at 0x3C pointing to 0x80 (128)
    dos_header = bytearray(128)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 128)

    # PE Signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    machine = 0x8664 if is_64bit else 0x014C
    num_sections = 1
    timestamp = 0x66000000  # realistic timestamp
    ptr_sym_table = 0
    num_symbols = 0
    size_opt_hdr = 240 if is_64bit else 224
    chars = 0x0002 | (0x2000 if is_dll else 0)  # EXECUTABLE_IMAGE (+ DLL)

    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        timestamp,
        ptr_sym_table,
        num_symbols,
        size_opt_hdr,
        chars,
    )

    # Optional Header
    opt_magic = 0x020B if is_64bit else 0x010B
    major_linker = 14
    minor_linker = 0
    size_of_code = len(raw_section_data)
    size_of_init = 0
    size_of_uninit = 0
    ep_rva = 0x1000
    base_of_code = 0x1000
    image_base = 0x140000000 if is_64bit else 0x00400000
    sec_align = 0x1000
    file_align = 0x200
    subsystem = 2  # GUI
    dll_chars = 0x0140  # DYNAMIC_BASE | NX_COMPAT
    size_headers = 0x200
    size_image = 0x3000

    if is_64bit:
        # Standard fields (24 bytes)
        opt_standard = struct.pack(
            "<HBBIIIII",
            opt_magic,
            major_linker,
            minor_linker,
            size_of_code,
            size_of_init,
            size_of_uninit,
            ep_rva,
            base_of_code,
        )
        # Windows-specific fields starting with ImageBase (8 bytes)
        opt_windows = struct.pack(
            "<QIIHHHHHHIIIIHHQQQQII",
            image_base,
            sec_align,
            file_align,
            6, 0,  # OS version
            0, 0,  # Image version
            6, 0,  # Subsystem version
            0,     # Win32VersionValue
            size_image,
            size_headers,
            0,     # CheckSum
            subsystem,
            dll_chars,
            0x100000, 0x1000,  # Stack reserve / commit
            0x100000, 0x1000,  # Heap reserve / commit
            0,     # LoaderFlags
            16,    # NumberOfRvaAndSizes
        )
    else:
        # Standard fields (28 bytes)
        opt_standard = struct.pack(
            "<HBBIIIIII",
            opt_magic,
            major_linker,
            minor_linker,
            size_of_code,
            size_of_init,
            size_of_uninit,
            ep_rva,
            base_of_code,
            0,  # BaseOfData
        )
        opt_windows = struct.pack(
            "<IIIHHHHHHIIIIHHIIIIII",
            image_base,
            sec_align,
            file_align,
            6, 0,
            0, 0,
            6, 0,
            0,
            size_image,
            size_headers,
            0,
            subsystem,
            dll_chars,
            0x100000, 0x1000,
            0x100000, 0x1000,
            0,
            16,
        )

    # Data directories (16 entries of 8 bytes = 128 bytes of zeros)
    data_dirs = b"\x00" * 128

    # Section Header (40 bytes)
    sec_name_bytes = (section_name.encode("ascii") + b"\x00" * 8)[:8]
    sec_virt_size = 0x1000
    sec_virt_addr = 0x1000
    sec_raw_size = len(raw_section_data)
    sec_raw_ptr = 0x200  # aligned to file_align
    sec_reloc_ptr = 0
    sec_lineno_ptr = 0
    sec_num_reloc = 0
    sec_num_lineno = 0

    # Characteristics
    # 0x20000000 = MEM_EXECUTE, 0x40000000 = MEM_READ, 0x80000000 = MEM_WRITE
    sec_chars = 0x20000000 | 0x40000000
    if writable_and_executable:
        sec_chars |= 0x80000000

    section_hdr = struct.pack(
        "<8sIIIIIIHHI",
        sec_name_bytes,
        sec_virt_size,
        sec_virt_addr,
        sec_raw_size,
        sec_raw_ptr,
        sec_reloc_ptr,
        sec_lineno_ptr,
        sec_num_reloc,
        sec_num_lineno,
        sec_chars,
    )

    # Pad header to sec_raw_ptr (0x200 = 512 bytes)
    header_content = dos_header + pe_sig + coff_header + opt_standard + opt_windows + data_dirs + section_hdr
    pad_len = 0x200 - len(header_content)
    if pad_len > 0:
        header_content += b"\x00" * pad_len

    full_binary = header_content + raw_section_data
    with open(target_path, "wb") as f:
        f.write(full_binary)

    return target_path
