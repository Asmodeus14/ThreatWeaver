"""ThreatWeaver scanner package.

Exports are resolved lazily (PEP 562) so that importing a lightweight submodule such as
``threatweaver.scanner.feature_extractor`` does not pull in PyTorch via the inference
engine. Isolated parsing workers depend on this to stay small.
"""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "StaticPEParser": "pe_parser",
    "PEAnalysisResult": "pe_parser",
    "PEValidationError": "pe_parser",
    "FileTooLargeError": "pe_parser",
    "InvalidPEMagicError": "pe_parser",
    "CorruptPEStructureError": "pe_parser",
    "SectionInfo": "pe_parser",
    "compute_shannon_entropy": "pe_parser",
    "compute_byte_histogram": "pe_parser",
    "FeatureExtractor": "feature_extractor",
    "ExtractedFeatures": "feature_extractor",
    "SCHEMA_VERSION": "feature_extractor",
    "FEATURE_DIM": "feature_extractor",
    "InferenceEngine": "inference",
    "ScanResult": "inference",
    "ScanVerdict": "inference",
    "ScanService": "scan_service",
    "PE_EXTENSIONS": "scan_service",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module 'threatweaver.scanner' has no attribute {name!r}")
    value = getattr(import_module(f"threatweaver.scanner.{module}"), name)
    globals()[name] = value
    return value
