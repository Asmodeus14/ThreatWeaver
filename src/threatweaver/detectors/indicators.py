"""Human-readable static indicators derived from thrember raw features.

Indicators are *supporting evidence* shown next to the model score. They are deliberately
worded as observations ("imports APIs commonly used for process injection") rather than
conclusions: many legitimate programs (installers, debuggers, security tools, DRM) trip
some of them. They do not change the verdict on their own.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Set

PACKER_SECTIONS = {
    ".upx0": "UPX", ".upx1": "UPX", ".upx2": "UPX", "upx0": "UPX", "upx1": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".themida": "Themida", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".petite": "Petite",
    ".pec": "PECompact", ".pec1": "PECompact", ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
    ".perplex": "Perplex", ".yp": "Y0da", ".packed": "generic packer", ".rlpack": "RLPack",
}
STANDARD_ENTRY_SECTIONS = {".text", "code", ".code", "text", ".itext", "init", "page"}

API_COMBOS = [
    ("process_injection", "high", "process injection",
     [{"virtualallocex"}, {"writeprocessmemory"}, {"createremotethread", "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc"}]),
    ("process_hollowing", "high", "process hollowing",
     [{"ntunmapviewofsection", "zwunmapviewofsection"}, {"setthreadcontext", "wow64setthreadcontext"}, {"resumethread"}]),
    ("keylogging", "medium", "keyboard capture",
     [{"setwindowshookexa", "setwindowshookexw"}, {"getasynckeystate", "getkeystate", "getkeyboardstate"}]),
    ("credential_dumping", "high", "process memory dumping (e.g. credential theft)",
     [{"minidumpwritedump"}, {"openprocess"}]),
    ("anti_debugging", "low", "debugger detection",
     [{"isdebuggerpresent"}, {"checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa"}]),
    ("privilege_adjustment", "low", "enabling process privileges",
     [{"adjusttokenprivileges"}, {"lookupprivilegevaluea", "lookupprivilegevaluew"}]),
    ("service_persistence", "medium", "installing Windows services",
     [{"openscmanagera", "openscmanagerw"}, {"createservicea", "createservicew"}]),
    ("download_execute", "medium", "downloading and running files",
     [{"urldownloadtofilea", "urldownloadtofilew", "internetopenurla", "internetopenurlw", "winhttpopen"},
      {"shellexecutea", "shellexecutew", "winexec", "createprocessa", "createprocessw"}]),
]


@dataclass
class Indicator:
    id: str
    severity: str  # "low" | "medium" | "high"
    text: str


def _lower_imports(imports: Dict[str, Iterable[str]]) -> Set[str]:
    out: Set[str] = set()
    for funcs in (imports or {}).values():
        for f in funcs or []:
            if isinstance(f, str):
                out.add(f.lower())
    return out


def indicators_from_raw(raw: Dict[str, Any], now: float | None = None) -> List[Indicator]:
    ind: List[Indicator] = []
    now = now or time.time()
    general = raw.get("general") or {}
    if not general.get("is_pe"):
        return ind

    sec = raw.get("section") or {}
    sections = sec.get("sections") or []
    entry = (sec.get("entry") or "").strip()
    names = {(s.get("name") or "").strip().lower(): s for s in sections}

    packers = sorted({PACKER_SECTIONS[n] for n in names if n in PACKER_SECTIONS})
    if packers:
        ind.append(Indicator("packer_sections", "medium", f"Section names typical of a packer/protector: {', '.join(packers)}."))

    wx = [s.get("name") for s in sections if {"MEM_EXECUTE", "MEM_WRITE"} <= set(s.get("props") or [])]
    if wx:
        ind.append(Indicator("writable_executable_section", "medium",
                             f"Section(s) both writable and executable: {', '.join(map(str, wx[:4]))}."))

    high_ent = [s for s in sections if (s.get("entropy") or 0) > 7.2 and (s.get("size") or 0) >= 4096]
    if high_ent:
        ind.append(Indicator("high_entropy_section", "low",
                             f"High-entropy section(s) suggesting compressed or encrypted content: "
                             f"{', '.join(f'{s.get('name')} ({s.get('entropy'):.2f})' for s in high_ent[:3])}."))

    unpack = [s.get("name") for s in sections if (s.get("size") or 0) == 0 and (s.get("vsize") or 0) >= 0x10000]
    if unpack:
        ind.append(Indicator("empty_raw_large_virtual", "medium",
                             f"Section(s) with no file data but large memory size (typical unpacking target): {', '.join(map(str, unpack[:3]))}."))

    if entry and entry.lower() not in STANDARD_ENTRY_SECTIONS:
        ent = names.get(entry.lower())
        writable = ent is not None and "MEM_WRITE" in (ent.get("props") or [])
        ind.append(Indicator("unusual_entry_section", "medium" if writable else "low",
                             f"Entry point is in section '{entry}'" + (" which is writable." if writable else ", not a standard code section.")))

    ov = sec.get("overlay") or {}
    if (ov.get("size") or 0) > 0:
        ratio, ent = ov.get("size_ratio") or 0, ov.get("entropy") or 0
        if ratio >= 0.3 and ent > 7.0:
            ind.append(Indicator("encrypted_overlay", "medium",
                                 f"Large high-entropy overlay appended after the PE image ({ratio:.0%} of the file, entropy {ent:.2f})."))
        elif ratio >= 0.5:
            ind.append(Indicator("large_overlay", "low", f"Data appended after the PE image makes up {ratio:.0%} of the file."))

    # Compile timestamps are NOT used: Windows' reproducible builds store a hash in this field, so
    # "future" timestamps fired on 55% of signed System32 executables (measured) — pure noise.

    imports = raw.get("imports") or {}
    funcs = _lower_imports(imports)
    for cid, severity, label, groups in API_COMBOS:
        if all(funcs & g for g in groups):
            hits = sorted(set().union(*(funcs & g for g in groups)))
            ind.append(Indicator(f"api_{cid}", severity,
                                 f"Imports APIs commonly used for {label} ({', '.join(hits[:5])}); also used by some legitimate tools."))
    if 0 < len(funcs) <= 4 and funcs & {"getprocaddress", "loadlibrarya", "loadlibraryw", "ldrgetprocedureaddress"}:
        ind.append(Indicator("minimal_imports_dynamic_resolution", "medium",
                             f"Only {len(funcs)} imported function(s), including dynamic API resolution (common in packed code)."))
    elif not funcs and not sections == []:
        ind.append(Indicator("no_imports", "low", "No imported functions (unusual for a normal program)."))

    auth = raw.get("authenticode") or {}
    if auth.get("num_certs"):
        if auth.get("self_signed"):
            ind.append(Indicator("self_signed_certificate", "medium", "Embedded signature uses a self-signed certificate."))
        if auth.get("parse_error"):
            ind.append(Indicator("malformed_signature", "medium", "Embedded signature could not be parsed."))
        if auth.get("no_countersigner"):
            ind.append(Indicator("no_signature_timestamp", "low", "Signature has no countersignature (timestamp)."))

    warnings = raw.get("pefilewarnings") or []
    if len(warnings) >= 3:  # 1-2 warnings occur on ~17% of signed System32 binaries (measured)
        ind.append(Indicator("pe_structure_warnings", "medium",
                             f"The PE parser reported {len(warnings)} structural warning(s) (malformed or unusual headers)."))
    return ind


def as_dicts(indicators: List[Indicator]) -> List[Dict[str, str]]:
    return [asdict(i) for i in indicators]
