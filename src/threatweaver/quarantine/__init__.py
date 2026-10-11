"""ThreatWeaver quarantine package."""

from threatweaver.quarantine.manager import (
    QuarantineManager,
    QuarantineEntry,
    QuarantineError,
    CriticalSystemFileError,
    SymlinkReparsePointError,
    HashMismatchError,
    CRITICAL_WINDOWS_PATHS,
)

__all__ = [
    "QuarantineManager",
    "QuarantineEntry",
    "QuarantineError",
    "CriticalSystemFileError",
    "SymlinkReparsePointError",
    "HashMismatchError",
    "CRITICAL_WINDOWS_PATHS",
]
