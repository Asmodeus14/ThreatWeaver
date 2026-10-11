# ThreatWeaver Implementation Plan & Roadmap

## 1. Project Overview & Architecture Vision

**ThreatWeaver** is a local-first, research-driven malware detection and static analysis engine with an architectural path toward real-time Windows endpoint protection and eventual compatibility with the Nyx operating system.

ThreatWeaver avoids simplistic "AI classifier" claims by explicitly differentiating between:
1. **Confirmed Malicious** (verified malware signatures / high-confidence multi-evidence classification)
2. **Suspicious** (anomalous characteristics, suspicious section entropy, suspicious imports, above classification threshold)
3. **Unfamiliar / Novel** (out-of-distribution sample with high embedding distance from known clusters)
4. **Likely Benign** (well-known benign attributes, low malicious probability, low anomaly score)
5. **Unsupported / Analysis Error** (corrupt PE header, malformed structure, architecture mismatch)

---

## 2. Phased Implementation Roadmap

```text
[Phase 1: Research & ML Engine]
   ├── Modular PyTorch Architecture (Encoder + Classifier Head + Embedding Projector)
   ├── Reproducible Feature Pipeline & Temporal Split Protocol
   ├── Continual Learning Engine (4 Strategies: None, Random, Uncertainty, Uncertainty+Diversity)
   └── Rigorous Metrics: Macro-F1, FPR, Catastrophic Forgetting, Novelty Detection
          │
[Phase 2: Static PE Analysis Pipeline]
   ├── Hardened Windows PE Parser (pefile, bounded memory/time, untrusted input handling)
   ├── Strict Zero-Execution Guarantees (No wine/python/powershell/emulator execution)
   ├── Feature Extractor (Entropy, PE headers, imports/exports, sections, version info, strings)
   └── Schema Versioning (Matching Model Features strictly)
          │
[Phase 3: On-Demand Windows Scanner & Reporting]
   ├── CLI and Windows Scanning Application
   ├── Scan Service with Thread Pool, Cancellation, Progress Streaming
   ├── Calibrated Probabilities & Evidence Attribution
   └── Local JSON/HTML Scan History & Sanitized Report Exporter
          │
[Phase 4: Safe Reversible Quarantine & Recovery]
   ├── Strict Validation & Confirmation Workflow
   ├── Restricted Quarantine Storage with Access Control
   ├── Atomic Moves with Pre/Post SHA-256 Hash Verification
   ├── Path Traversal, Reparse-Point & Symlink Protection
   ├── Critical Windows Directory Protection Shield
   └── Audit Logging & Safe Restore Verification (with Dry-Run support)
          │
[Phase 5: Real-Time Protection Research & Endpoint Architecture]
   ├── User-Mode Filesystem Monitor (ReadDirectoryChangesW / USN Journal abstraction)
   ├── Event De-duplication & Storm Throttling
   ├── Observational Safe-Monitoring Mode (Zero blocking)
   └── Complete Minifilter Driver Architecture, Threat Model, and Signing Plan
```

---

## 3. Detailed Milestone Breakdown

### Milestone 1: Core Framework, Static Feature Extraction & PE Hardening
- **Objective**: Build safe, robust PE parsing and feature extraction that converts raw PE files into versioned numeric vectors without ever executing code.
- **Components**:
  - `threatweaver.scanner.pe_parser`: Safe wrapper around PE structural validation (headers, optional headers, data directories). Handles truncated, corrupt, and oversized files.
  - `threatweaver.scanner.feature_extractor`: Extracts section entropy, import hashes, symbol counts, header fields, and byte histogram/entropy summary. Total 256-dim standardized feature vector (Schema v1).
  - Test fixtures: Benign synthetic PE files and malformed test inputs.
- **Acceptance Criteria**:
  - Parsing malformed or truncated inputs raises handled exceptions without crashing.
  - Memory usage is strictly bounded.
  - No system execution APIs are invoked.

### Milestone 2: PyTorch Model, Embeddings, & Novelty Detection
- **Objective**: Modular neural network model supporting representation learning, classification, and calibrated novelty detection.
- **Components**:
  - `threatweaver.models.encoder`: Residual Multi-Layer Perceptron (ResMLP) with LayerNorm and Dropout for tabular static features.
  - `threatweaver.models.classifier`: Calibrated classification head (benign vs malware + family output).
  - `threatweaver.models.novelty`: Embedding-space novelty detector using Mahalanobis distance / k-NN cosine distance against known benign and malware prototype clusters.
  - Safe model checkpointing (only model weights, schema version, and normalization statistics).
- **Acceptance Criteria**:
  - Validated inference on CPU and CUDA.
  - Deterministic forward pass and reproducible evaluation.
  - Threshold selection calibrated on validation data only (no test leakage).

### Milestone 3: Continual Learning & Catastrophic Forgetting Benchmark
- **Objective**: Compare 4 replay memory strategies under identical memory and labeling budgets:
  1. *No replay* (naive fine-tuning)
  2. *Random replay* (uniform random sample from replay buffer)
  3. *Uncertainty-guided replay* (samples with highest prediction entropy / margin)
  4. *Uncertainty-plus-diversity replay* (entropy-weighted k-means clustering in embedding space)
- **Components**:
  - `threatweaver.learning.replay_buffer`: Bounded memory buffer with configurable eviction.
  - `threatweaver.learning.selection`: Sample selection policies.
  - `threatweaver.learning.trainer`: Chronological training loop simulating sequential malware arrival batches.
  - `threatweaver.evaluation.forgetting`: Catastrophic forgetting metric ($F_t$), Backward Transfer ($BWT$), Macro-F1, FPR on benign files.
- **Acceptance Criteria**:
  - Benchmark script runs reproducible multi-seed experiment and outputs structured comparison table and metrics report.

### Milestone 4: On-Demand Windows Scanner & Scan Service
- **Objective**: Usable, responsive scanning service and CLI/UI interface for single files and recursive directory scanning.
- **Components**:
  - `threatweaver.scanner.scan_service`: Multi-threaded background scanner with progress callbacks, cancellation tokens, and queue management.
  - `threatweaver.reporting.report`: Local scan history, JSON report export, evidence explanation generator (top contributing static features).
  - `threatweaver.app.cli`: Rich CLI with formatted tables, progress bars, interactive confirmation, and detailed inspection views.
- **Acceptance Criteria**:
  - Handles directories with nested files, ignores inaccessible or system-locked files gracefully.
  - Clean cancellation within 500ms of user interrupt.
  - Output clearly distinguishes benign, suspicious, unfamiliar, and malformed files.

### Milestone 5: Safe Reversible Quarantine & Recovery
- **Objective**: Secure file isolation and restoration engine with defense against path traversal, symlink hijacking, and accidental deletion.
- **Components**:
  - `threatweaver.quarantine.manager`: Atomic quarantine with hash verification, metadata preservation (`quarantine.manifest.json`), obfuscated storage (XOR mask to prevent accidental execution or scanner re-triggering), audit log.
  - System directory protector: Refuses to quarantine system-critical paths (`System32`, `Windows`, `Boot`, etc.).
  - Restore functionality: Verified reversal with user confirmation.
- **Acceptance Criteria**:
  - Zero data loss: Hashes verified before move, after move, and after restore.
  - Symlink / directory traversal attacks rejected.
  - Dry-run mode allows verifying actions safely.

### Milestone 6: Real-Time Protection Research & Architecture Documentation
- **Objective**: Thorough architectural foundation and observational file monitor for Windows.
- **Components**:
  - User-mode filesystem watcher (`threatweaver.scanner.watcher`) based on change notification queue with event deduplication.
  - Non-blocking observational mode (alerts only, zero interference).
  - Architecture specifications: `docs/realtime_threat_model.md`, `docs/minifilter_architecture.md`, `docs/nyx_compatibility.md`.
- **Acceptance Criteria**:
  - Observational watcher detects file creation/modification events and queues for static scan without blocking I/O.
  - Full driver specification documents signing, recovery, and kernel-user communication mechanisms.

---

## 4. Current Status & Progress Tracking

| Milestone | Status | Details |
|---|---|---|
| Milestone 1: PE Hardening & Static Extraction | **Completed** | Strict bounded PE parsing, 256-dim schema v1.0, anomaly detection, W^X violations |
| Milestone 2: PyTorch Model & Novelty Detection | **Completed** | ResMLP encoder, calibrated classifier, L2-normalized embeddings, prototype novelty detector |
| Milestone 3: Continual Learning Experiment | **Completed** | 4 replay strategies benchmarked, catastrophic forgetting ($F_T$) & BWT evaluated, multi-seed reports |
| Milestone 4: On-Demand Scanner & Reporting | **Completed** | Multi-threaded scan service, cancellation, rich CLI, evidence attribution, local history |
| Milestone 5: Safe Reversible Quarantine | **Completed** | Pre/post SHA-256 verification, XOR neutralization, Windows path shield, audit log, dry-run |
| Milestone 6: Real-Time Research & Architecture | **Completed** | Observational user-mode watcher + complete Minifilter driver specification & threat model |
| Milestone 7: Master Apple UI & Threat Network | **Completed** | 9-screen Apple Minimalist UI, interactive HTML5 Canvas Threat Network with spring physics, 4-tab contextual details panel, Family Explorer, and Continual Learning Timeline |

---

## 5. Verification & Acceptance Results

- **Automated Test Suite**: 48/48 tests passing across PE parsing, feature extraction, PyTorch models, continual learning, quarantine isolation, scan service, CLI, and HTTP server REST API (`tests/`).
- **Continual Learning Experiment**: Successfully trained on 5 temporal batches, saved calibrated checkpoint to `artifacts/checkpoints/threatweaver_v1.pt`, generated structured results in `reports/continual_learning_results.json`.
- **Live Scanning Validation**: Successfully scanned local executables with streaming progress, formatted tables, and generated `reports/self_scan.json` and `reports/self_scan.md`.
- **Quarantine Validation**: Completed full quarantine, XOR neutralization, and restoration cycle with exact SHA-256 integrity verification.
- **Master UI & Threat Network**: Delivered zero-dependency Canvas-based relationship explorer, macOS-inspired 9-screen layout, contextual attribution panel, and real-time REST integration.


---

## 5. Security & Architectural Risks

1. **Untrusted PE Parsing**: Parsing malformed PE files in Python can trigger memory issues or recursion limits in naive parsers. *Mitigation*: Bounded header reads, strict bounds checking, defensive exception wrapping around `pefile`.
2. **Replay Buffer Poisoning**: Continual learning on unverified labels can degrade model accuracy. *Mitigation*: Strict verified-sample requirement for replay buffer inclusion.
3. **Quarantine Abuse**: A malicious actor might trick the scanner into quarantining vital operating system binaries. *Mitigation*: Protected paths blacklist (`System32`, `SysWOW64`, `explorer.exe`, etc.) and mandatory human confirmation.
4. **False Positive Impact**: Incorrectly labeling business software as malware causes disruption. *Mitigation*: Separate "Suspicious", "Unfamiliar", and "Confirmed Malicious" labels; FPR metrics tracked separately on clean datasets.
