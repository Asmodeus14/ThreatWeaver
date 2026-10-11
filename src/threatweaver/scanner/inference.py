"""ThreatWeaver Inference Engine.

Performs static model inference, novelty calibration check, and evidence attribution
without ever executing scanned files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch

from threatweaver.data.preprocessing import FeatureScaler
from threatweaver.models.classifier import ThreatClassifier, load_checkpoint
from threatweaver.models.novelty import NoveltyAssessment, NoveltyDetector
from threatweaver.scanner.feature_extractor import ExtractedFeatures, FeatureExtractor, SCHEMA_VERSION


class ScanVerdict(str, Enum):
    """Calibrated security verdict for a scanned file."""
    LIKELY_BENIGN = "Likely Benign"
    SUSPICIOUS = "Suspicious"
    UNFAMILIAR = "Unfamiliar / Out-of-Distribution"
    UNSUPPORTED = "Unsupported Format"
    ANALYSIS_ERROR = "Analysis Error"


@dataclass
class ScanResult:
    """Complete static analysis and inference result for an individual file."""
    file_path: str
    file_name: str
    file_size_bytes: int
    sha256: str
    verdict: ScanVerdict
    malware_probability: float  # Calibrated probability (0.0 to 1.0)
    novelty_score: float        # Distance in embedding space
    is_novel: bool
    evidence_points: List[str]
    scan_duration_ms: float
    model_version: str
    raw_indicators: List[str] = field(default_factory=list)
    nearest_known_cluster: Optional[str] = None
    warning_message: Optional[str] = None


class InferenceEngine:
    """Manages model loading, normalization, and calibrated inference."""

    def __init__(
        self,
        checkpoint_path: Optional[str | Path] = None,
        device: str = "cpu",
        classification_threshold: float = 0.50,
    ):
        self.device = torch.device(device)
        self.threshold = classification_threshold
        self.model: Optional[ThreatClassifier] = None
        self.scaler: Optional[FeatureScaler] = None
        self.novelty_detector: Optional[NoveltyDetector] = None
        self.extractor = FeatureExtractor()
        self.checkpoint_loaded: bool = False
        self.model_version = "Unloaded"

        if checkpoint_path and Path(checkpoint_path).is_file():
            self.load_model(checkpoint_path)

    def load_model(self, checkpoint_path: str | Path) -> None:
        """Loads and initializes model from safe checkpoint."""
        ckpt_path = Path(checkpoint_path).resolve()
        model, meta = load_checkpoint(ckpt_path, device=self.device)
        self.model = model
        self.model.eval()

        # Reconstruct scaler
        if meta.get("feature_mean") and meta.get("feature_std"):
            self.scaler = FeatureScaler.from_dict({
                "fitted": True,
                "mean": meta["feature_mean"],
                "std": meta["feature_std"],
            })
        else:
            self.scaler = None

        # Reconstruct novelty detector with calibrated threshold
        nov_thresh = meta.get("novelty_threshold", 0.40)
        self.novelty_detector = NoveltyDetector(calibrated_threshold=nov_thresh)
        self.checkpoint_loaded = True
        self.model_version = f"ThreatWeaver-v{meta.get('schema_version', '1.0')}"

    def analyze_file(self, file_path: str | Path) -> ScanResult:
        """Analyzes a file from path and produces a calibrated ScanResult."""
        import time
        start_t = time.time()
        path = Path(file_path).resolve()

        if not path.is_file():
            return ScanResult(
                file_path=str(path),
                file_name=path.name,
                file_size_bytes=0,
                sha256="",
                verdict=ScanVerdict.ANALYSIS_ERROR,
                malware_probability=0.0,
                novelty_score=0.0,
                is_novel=False,
                evidence_points=["File does not exist or is inaccessible."],
                scan_duration_ms=0.0,
                model_version=self.model_version,
                warning_message="Path is not a regular file.",
            )

        # 1. Static feature extraction
        extracted = self.extractor.extract_from_file(path)
        extract_time_ms = (time.time() - start_t) * 1000.0

        if not extracted.is_valid_pe:
            error_text = extracted.raw_metadata.get("error", "Not a valid Windows PE binary.")
            return ScanResult(
                file_path=str(path),
                file_name=path.name,
                file_size_bytes=extracted.file_size,
                sha256=extracted.sha256,
                verdict=ScanVerdict.UNSUPPORTED,
                malware_probability=0.0,
                novelty_score=0.0,
                is_novel=False,
                evidence_points=[f"Validation detail: {error_text}"],
                scan_duration_ms=extract_time_ms,
                model_version=self.model_version,
                raw_indicators=extracted.detected_indicators,
                warning_message=error_text,
            )

        evidence: List[str] = list(extracted.detected_indicators)

        # 2. Check if model is loaded
        if not self.checkpoint_loaded or self.model is None:
            # Model is unavailable: explicitly warn without fabricating risk score
            return ScanResult(
                file_path=str(path),
                file_name=path.name,
                file_size_bytes=extracted.file_size,
                sha256=extracted.sha256,
                verdict=ScanVerdict.SUSPICIOUS if evidence else ScanVerdict.LIKELY_BENIGN,
                malware_probability=0.0,
                novelty_score=0.0,
                is_novel=False,
                evidence_points=evidence or ["Valid PE structure parsed."],
                scan_duration_ms=extract_time_ms,
                model_version="Model Not Loaded",
                raw_indicators=evidence,
                warning_message="Model checkpoint not loaded; reporting static structural indicators only.",
            )

        # 3. Model inference
        raw_feat = extracted.feature_vector
        if self.scaler is not None and self.scaler.fitted:
            norm_feat = self.scaler.transform(raw_feat.reshape(1, -1))[0]
        else:
            norm_feat = raw_feat

        x_tensor = torch.tensor(norm_feat.reshape(1, -1), dtype=torch.float32).to(self.device)

        with torch.no_grad():
            output = self.model(x_tensor)
            prob_malware = float(output.probabilities[0, 1].item())
            emb = output.embeddings[0].cpu().numpy()

        # 4. Novelty assessment
        is_novel = False
        novelty_score = 0.0
        nearest_cluster = None
        if self.novelty_detector is not None:
            nov_eval = self.novelty_detector.evaluate_novelty(emb)
            is_novel = nov_eval.is_novel
            novelty_score = nov_eval.novelty_score
            nearest_cluster = nov_eval.nearest_family
            if is_novel:
                evidence.append(
                    f"Out-of-distribution sample: embedding distance ({novelty_score:.2f}) "
                    f"exceeds calibrated threshold ({nov_eval.calibrated_threshold:.2f})."
                )

        # 5. Calibrated Verdict Assignment
        # Differentiate between Confirmed Malicious, Suspicious, Unfamiliar, Likely Benign
        if is_novel and prob_malware < 0.85:
            # High distance from training distribution and not overwhelming malicious signal
            verdict = ScanVerdict.UNFAMILIAR
            evidence.append("Sample characteristics differ from known benign and malicious baselines.")
        elif prob_malware >= self.threshold or (prob_malware >= 0.40 and len(evidence) >= 2):
            verdict = ScanVerdict.SUSPICIOUS
            evidence.append(f"Model static risk score: {prob_malware:.1%} (threshold {self.threshold:.1%}).")
        else:
            verdict = ScanVerdict.LIKELY_BENIGN
            evidence.append(f"Model static risk score: {prob_malware:.1%}; no anomalous characteristics observed.")

        total_time_ms = (time.time() - start_t) * 1000.0

        return ScanResult(
            file_path=str(path),
            file_name=path.name,
            file_size_bytes=extracted.file_size,
            sha256=extracted.sha256,
            verdict=verdict,
            malware_probability=prob_malware,
            novelty_score=novelty_score,
            is_novel=is_novel,
            evidence_points=evidence,
            scan_duration_ms=total_time_ms,
            model_version=self.model_version,
            raw_indicators=extracted.detected_indicators,
            nearest_known_cluster=nearest_cluster,
            warning_message=None,
        )
