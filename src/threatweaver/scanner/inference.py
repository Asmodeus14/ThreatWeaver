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
from threatweaver.models.classifier import ThreatClassifier, load_checkpoint, save_checkpoint
from threatweaver.models.novelty import NoveltyAssessment, NoveltyDetector, PrototypeCluster
from threatweaver.scanner.feature_extractor import ExtractedFeatures, FeatureExtractor, SCHEMA_VERSION
from threatweaver.scanner.hash_cache import CleanHashCache
from threatweaver.scanner.signature_verifier import WindowsSignatureVerifier


SHIPPED_CHECKPOINT_DIR = Path("artifacts/checkpoints")
VERDICT_POLICY_VERSION = "v0.1-policy-2"  # bump whenever verdict logic changes (invalidates cache)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()
LOCAL_MODELS_DIR = Path("artifacts/models/local")


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
        enable_signature_verifier: bool = True,
        enable_hash_cache: bool = True,
        cache_db_path: Optional[str | Path] = None,
    ):
        self.device = torch.device(device)
        self.threshold = classification_threshold
        self.checkpoint_path: Optional[Path] = Path(checkpoint_path).resolve() if checkpoint_path else None
        self._source_checkpoints: set = set()
        self.model: Optional[ThreatClassifier] = None
        self.scaler: Optional[FeatureScaler] = None
        self.novelty_detector: Optional[NoveltyDetector] = None
        self.extractor = FeatureExtractor()
        self.checkpoint_loaded: bool = False
        self.model_version = "Unloaded"
        self.signature_verifier = WindowsSignatureVerifier(enabled=enable_signature_verifier)
        self.hash_cache = CleanHashCache(db_path=cache_db_path, enabled=enable_hash_cache)

        if checkpoint_path and Path(checkpoint_path).is_file():
            self.load_model(checkpoint_path)

    def load_model(self, checkpoint_path: str | Path) -> None:
        """Loads and initializes model from safe checkpoint."""
        ckpt_path = Path(checkpoint_path).resolve()
        self.checkpoint_path = ckpt_path
        self._source_checkpoints.add(ckpt_path)
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

        # Reconstruct novelty detector with calibrated threshold and prototypes
        nov_thresh = meta.get("novelty_threshold", 0.40)
        self.novelty_detector = NoveltyDetector(calibrated_threshold=nov_thresh)
        if meta.get("prototypes"):
            for p_dict in meta["prototypes"]:
                self.novelty_detector.prototypes.append(
                    PrototypeCluster(
                        label=p_dict["label"],
                        family_name=p_dict["family_name"],
                        centroid=np.array(p_dict["centroid"], dtype=np.float32),
                        sample_count=p_dict.get("sample_count", 1),
                    )
                )
        self.checkpoint_loaded = True
        self.model_version = f"ThreatWeaver-v{meta.get('schema_version', '1.0')}"

    def cache_fingerprint(self) -> str:
        """Identifies everything that can change a verdict for identical file bytes."""
        import hashlib

        if self.checkpoint_path and self.checkpoint_path.is_file():
            key = (str(self.checkpoint_path), self.checkpoint_path.stat().st_mtime_ns)
            if getattr(self, "_ckpt_digest_key", None) != key:
                self._ckpt_digest = sha256_file(self.checkpoint_path)
                self._ckpt_digest_key = key
            ckpt_digest = self._ckpt_digest
        else:
            ckpt_digest = "no-model"
        nd = self.novelty_detector
        parts = [
            VERDICT_POLICY_VERSION,
            ckpt_digest if self.checkpoint_loaded else "no-model",
            f"thr={self.threshold:.6f}",
            f"tau={nd.threshold:.6f}" if nd else "tau=none",
            f"protos={len(nd.prototypes)}" if nd else "protos=0",
            f"sig={int(self.signature_verifier.enabled)}",
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]

    def _is_protected_checkpoint(self, path: Path) -> bool:
        """Shipped checkpoints and any checkpoint this engine loaded from are read-only."""
        resolved = path.resolve()
        if resolved in self._source_checkpoints:
            return True
        try:
            resolved.relative_to(SHIPPED_CHECKPOINT_DIR.resolve())
            return True
        except ValueError:
            return False

    def save_state(self, target_path: Optional[str | Path] = None, reason: str = "local update") -> Path:
        """Saves the current model state as a NEW versioned checkpoint and returns its path.

        Never overwrites a shipped checkpoint (artifacts/checkpoints/) or the file the
        engine was loaded from. Without target_path, writes
        artifacts/models/local/<parent-stem>_local_<UTC timestamp>.pt and records the
        lineage in artifacts/models/local/index.json.
        """
        import hashlib
        import json
        import time

        if self.model is None:
            raise ValueError("Cannot save state: No model loaded.")
        if target_path is not None:
            dest = Path(target_path).resolve()
            if self._is_protected_checkpoint(dest):
                raise PermissionError(f"Refusing to overwrite protected checkpoint: {dest}")
        else:
            parent_stem = self.checkpoint_path.stem.split("_local_")[0] if self.checkpoint_path else "threatweaver"
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            dest = (LOCAL_MODELS_DIR / f"{parent_stem}_local_{stamp}.pt").resolve()
            n = 1
            while dest.exists():
                dest = (LOCAL_MODELS_DIR / f"{parent_stem}_local_{stamp}_{n}.pt").resolve()
                n += 1
        dest.parent.mkdir(parents=True, exist_ok=True)
        parent_path = str(self.checkpoint_path) if self.checkpoint_path else None

        f_mean = self.scaler.mean.tolist() if (self.scaler and self.scaler.fitted) else None
        f_std = self.scaler.std.tolist() if (self.scaler and self.scaler.fitted) else None
        nov_thresh = self.novelty_detector.threshold if self.novelty_detector else 0.40
        protos = self.novelty_detector.to_dict_list() if self.novelty_detector else []

        saved_path = save_checkpoint(
            model=self.model,
            save_path=dest,
            feature_mean=f_mean,
            feature_std=f_std,
            novelty_threshold=nov_thresh,
            prototypes=protos,
            metadata={
                "description": "Locally modified ThreatWeaver model",
                "parent_checkpoint": parent_path,
                "reason": reason,
            },
            sign=True,
        )
        self.checkpoint_path = saved_path

        index_path = saved_path.parent / "index.json"
        try:
            index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.is_file() else []
        except Exception:
            index = []
        index.append({
            "path": str(saved_path),
            "parent": parent_path,
            "reason": reason,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sha256": hashlib.sha256(saved_path.read_bytes()).hexdigest(),
            "prototypes": len(protos),
        })
        index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
        return saved_path

    def register_prototype_from_sample(
        self,
        file_path: str | Path,
        label: int,
        family_name: str,
        persist: bool = False,
    ) -> Dict[str, Any]:
        """Extracts embedding from sample and registers it as a new prototype centroid (Option A)."""
        p = Path(file_path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Sample file not found: {p}")
        if self.model is None or self.novelty_detector is None:
            raise ValueError("Model or Novelty Detector not initialized.")

        extracted = self.extractor.extract_from_file(p)
        if not extracted.is_valid_pe:
            raise ValueError(f"File {p.name} is not a valid Windows PE binary.")

        raw_feat = extracted.feature_vector
        if self.scaler is not None and self.scaler.fitted:
            norm_feat = self.scaler.transform(raw_feat.reshape(1, -1))[0]
        else:
            norm_feat = raw_feat

        x_tensor = torch.tensor(norm_feat.reshape(1, -1), dtype=torch.float32).to(self.device)
        self.model.eval()
        with torch.no_grad():
            out = self.model(x_tensor)
            emb = out.embeddings[0].cpu().numpy()

        proto = self.novelty_detector.add_prototype(
            centroid=emb,
            label=label,
            family_name=family_name,
            sample_count=1,
        )

        # Invalidate cache for this file so rescans reflect the newly registered prototype
        if self.hash_cache.enabled and extracted.sha256:
            self.hash_cache.remove(extracted.sha256)

        saved_to = None
        if persist:
            saved_to = str(self.save_state(reason=f"prototype '{family_name}' registered from {p.name}"))

        return {
            "status": "success",
            "family_name": proto.family_name,
            "label": proto.label,
            "total_prototypes": len(self.novelty_detector.prototypes),
            "sha256": extracted.sha256,
            "file_name": p.name,
            "saved_checkpoint": saved_to,
        }


    def analyze_file(
        self,
        file_path: str | Path,
        bypass_cache: bool = False,
        bypass_signature: bool = False,
    ) -> ScanResult:
        """Analyzes a file using multi-tier triage (Cache -> Authenticode -> Static PE -> Neural)."""
        import hashlib
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

        try:
            file_size = path.stat().st_size
        except OSError:
            file_size = 0

        # Content hash first: the cache key is what the file IS, not what its timestamp says.
        try:
            file_sha256 = sha256_file(path) if file_size > 0 else ""
        except OSError:
            file_sha256 = ""
        fingerprint = self.cache_fingerprint()

        # Tier 0: cached verdict for identical bytes under the identical engine
        if self.hash_cache.enabled and not bypass_cache and file_sha256:
            cached_res = self.hash_cache.lookup(file_sha256, fingerprint, file_path=path)
            if cached_res is not None:
                return cached_res

        # Tier 1: Windows Authenticode & System Catalog Verification (< 1-15 ms)
        if self.signature_verifier.enabled and not bypass_signature and file_size > 0:
            sig_status = self.signature_verifier.verify_file(path)
            if sig_status.is_trusted:
                sig_duration = (time.time() - start_t) * 1000.0

                signer_desc = f" (Signer: {sig_status.subject})" if sig_status.subject else ""
                sig_res = ScanResult(
                    file_path=str(path),
                    file_name=path.name,
                    file_size_bytes=file_size,
                    sha256=file_sha256,
                    verdict=ScanVerdict.LIKELY_BENIGN,
                    malware_probability=0.001,
                    novelty_score=0.0,
                    is_novel=False,
                    evidence_points=[
                        f"Valid trusted {sig_status.provider} digital signature verified by Windows Trust Provider{signer_desc}.",
                        "Cryptographic integrity confirmed; bypassed deep neural inference.",
                    ],
                    scan_duration_ms=sig_duration,
                    model_version=f"Authenticode ({sig_status.provider})",
                    raw_indicators=[],
                    nearest_known_cluster=None,
                    warning_message=None,
                )
                if self.hash_cache.enabled and file_sha256:
                    self.hash_cache.record_scan_result(sig_res, fingerprint, source="Authenticode")
                return sig_res

        # Tier 2: Static feature extraction
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
        structural_anomalies = extracted.raw_metadata.get("structural_anomalies", [])
        has_critical_anomaly = len(structural_anomalies) > 0

        if is_novel and prob_malware < 0.85:
            # High distance from training distribution and not overwhelming malicious signal
            verdict = ScanVerdict.UNFAMILIAR
            evidence.append("Sample characteristics differ from known benign and malicious baselines.")
        elif prob_malware >= self.threshold or (prob_malware >= 0.40 and has_critical_anomaly):
            verdict = ScanVerdict.SUSPICIOUS
            evidence.append(f"Model static risk score: {prob_malware:.1%} (threshold {self.threshold:.1%}).")
        else:
            verdict = ScanVerdict.LIKELY_BENIGN
            evidence.append(f"Model static risk score: {prob_malware:.1%}; no anomalous characteristics observed.")

        total_time_ms = (time.time() - start_t) * 1000.0

        res = ScanResult(
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

        if self.hash_cache.enabled and extracted.is_valid_pe and extracted.sha256:
            self.hash_cache.record_scan_result(res, fingerprint, source="Neural")

        return res
