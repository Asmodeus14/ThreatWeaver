"""Process isolation for parsing untrusted files."""

from threatweaver.sandboxing.pool import ExtractionFailure, ExtractionPool

__all__ = ["ExtractionPool", "ExtractionFailure"]
