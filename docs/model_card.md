# ThreatWeaver Model Card

## 1. Model Overview
- **Model Name**: ThreatWeaver ResMLP Classifier & Embedding Projector (v1.0)
- **Architecture**: Residual Multi-Layer Perceptron (ResMLP) with LayerNorm, GELU, Dropout, and L2-Normalized Embedding Projection Head.
- **Input Dimension**: 256 standardized static executable features (Schema v1.0).
- **Embedding Dimension**: 32-dimensional unit sphere ($\|\mathbf{e}\|_2 = 1.0$).
- **Output Classes**: 2 (Class 0: Benign, Class 1: Malicious; extensible to multi-family attribution).
- **Runtime Environment**: PyTorch CPU / CUDA acceleration.

---

## 2. Intended Use & Safety Scope
- **Primary Use**: Static malware pre-filtering, anomaly identification, and novelty detection on untrusted Windows PE binaries.
- **Out of Scope**:
  - Live exploit execution prevention.
  - In-memory script execution (PowerShell, VBScript, obfuscated macro analysis).
  - Standalone replacement for certified endpoint detection and response (EDR) or Microsoft Defender.
- **Explicit Principle**: A model prediction alone is NOT proof of maliciousness. The system classifies samples as *Likely Benign*, *Suspicious*, *Unfamiliar*, *Unsupported*, or *Error*, requiring multi-evidence attribution.

---

## 3. Calibration & Novelty Detection Parameters
- **Novelty Distance Metric**: Cosine distance ($d(\mathbf{u}, \mathbf{v}) = 1 - \mathbf{u} \cdot \mathbf{v}$).
- **Calibrated Novelty Threshold**: $\tau = 0.40$ (calibrated at 95th percentile of validation cluster distances).
- **Failure Modes & Limitations**:
  - **Packed / Heavily Encrypted Samples**: High entropy (>7.5) will flag samples as suspicious or unfamiliar, but static analysis cannot inspect obfuscated payloads without execution.
  - **Adversarial Section Padding**: An adversary adding millions of benign strings or null bytes can shift histogram features; mitigated by robust section-level anomaly checks.
