# ThreatWeaver Model Card

All facts below are read from the shipped checkpoint (`artifacts/checkpoints/threatweaver_v1.pt`) or from files in `artifacts/benchmarks/`. Updated 2026-11-21.

## 1. Model Overview
- **Model name**: ThreatWeaver neural classifier and embedding projector (schema 1.0).
- **Architecture (as shipped)**: plain MLP — Linear(256→256) + LayerNorm + GELU + Dropout → Linear(256→128) + LayerNorm + GELU + Dropout → Linear(128→128) embedding, L2-normalized; classification head Linear(128→64) + LayerNorm + GELU + Dropout → Linear(64→2). The `ResidualBlock` class exists in code but is **not used** by this checkpoint (0 residual blocks), because consecutive hidden sizes differ.
- **Parameters**: 124,482.
- **Input**: 256 standardized static features (schema v1.0). In training, 179 of the 256 features were constant (see Limitations).
- **Embedding dimension**: 128 (unit sphere).
- **Temperature**: T = 1.11 (post-hoc, fitted on validation logits).
- **Novelty**: cosine distance to 21 prototypes (10 benign + 10 malware k-means centroids, plus 1 user-registered); threshold τ = 0.305.
- **Output classes**: 2 (benign, malicious).
- **Runtime**: PyTorch, CPU or CUDA.

## 2. Training Data
- EMBER2024 *test* partitions only (Win64_test and Dot_Net_test), first records of the earliest weekly files, balanced by label: 3,500 train / 750 validation / 750 test, plus 500 challenge (evasive malware) samples. Source: `artifacts/benchmarks/embedding_dimension_results.json` → `metadata`.
- The official EMBER2024 train partitions (2023-09 → 2024-09) were not used.

## 3. Measured Performance (locked test split)
| Metric | Value |
| :--- | :---: |
| Macro-F1 | 0.868 |
| ROC-AUC | 0.937 |
| PR-AUC | 0.933 |
| Detection rate at 1% FPR | 0.180 |
| FPR at 95% recall | 0.329 |
| ECE | 0.046 |
| Novelty AUROC | 0.601 |
| Challenge malware flagged unfamiliar | 22.2% |

The test split spans about 30 hours of submissions; these are experimental results, not operational performance.

**Operational sanity check (2026-11-21):** with the Authenticode tier disabled, 38 of 200 System32 `.exe` files (19%) scored P(malware) ≥ 0.5.

## 4. Intended Use & Scope
- **Use**: research and analyst triage of untrusted Windows PE files without executing them.
- **Not for**: real-time protection, script/macro analysis, or replacing Microsoft Defender or an EDR.
- A model score alone is not proof of maliciousness. Verdicts: *Likely Benign*, *Suspicious*, *Unfamiliar*, *Unsupported*, *Analysis Error*.

## 5. Known Limitations
- **Training/inference feature mismatch**: training vectors come from `harmonize_ember_record` (EMBER JSON), which reads several keys absent from EMBER2024 v3, leaving 179 of 256 features constant. Scan-time vectors come from `FeatureExtractor` and populate those dimensions. Fix: roadmap 2.2 (official `thrember` features for both).
- **Non-deterministic import buckets**: dims 112–159 use Python `hash()`, which varies per process. Fix: roadmap 2.1.
- **Weak novelty detection** (AUROC 0.60).
- **Packed / encrypted samples**: static features cannot see unpacked payloads.
- **Adversarial padding / overlays** can shift histogram and string features.
