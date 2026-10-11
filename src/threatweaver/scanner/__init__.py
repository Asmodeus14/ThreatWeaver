"""ThreatWeaver scanner package."""

from threatweaver.scanner.pe_parser import (
    StaticPEParser,
    PEAnalysisResult,
    PEValidationError,
    FileTooLargeError,
    InvalidPEMagicError,
    CorruptPEStructureError,
    SectionInfo,
    compute_shannon_entropy,
    compute_byte_histogram,
)
from threatweaver.scanner.feature_extractor import (
    FeatureExtractor,
    ExtractedFeatures,
    SCHEMA_VERSION,
    FEATURE_DIM,
)
from threatweaver.scanner.inference import (
    InferenceEngine,
    ScanResult,
    ScanVerdict,
)
from threatweaver.scanner.scan_service import (
    ScanService,
    PE_EXTENSIONS,
)

__all__ = [
    "StaticPEParser",
    "PEAnalysisResult",
    "PEValidationError",
    "FileTooLargeError",
    "InvalidPEMagicError",
    "CorruptPEStructureError",
    "SectionInfo",
    "compute_shannon_entropy",
    "compute_byte_histogram",
    "FeatureExtractor",
    "ExtractedFeatures",
    "SCHEMA_VERSION",
    "FEATURE_DIM",
    "InferenceEngine",
    "ScanResult",
    "ScanVerdict",
    "ScanService",
    "PE_EXTENSIONS",
]
