# ThreatWeaver

**AI-Powered Malware Research Engine & Next-Generation Antivirus Prototype**

ThreatWeaver is a local-first malware detection research platform and defensive endpoint protection prototype designed to evolve into a lightweight Windows antivirus, with a future-compatible architecture for the Nyx operating system.

ThreatWeaver explicitly separates:
- **Likely Benign**: Verified legitimate executable attributes, low malicious probability, low anomaly score.
- **Suspicious**: Anomalous section entropy, W^X violations, suspicious imports, high classifier probability.
- **Unfamiliar / Out-of-Distribution**: High distance from validated clusters in embedding space.
- **Unsupported**: Non-PE files, oversized files (>100MB), corrupt structures.
- **Analysis Error**: Inaccessible paths, I/O failures.

> **Defensive Security Notice**: ThreatWeaver is a defensive research prototype and does not replace Microsoft Defender or commercial EDR software. It never executes untrusted code, never silences system controls, and never automatically deletes files.

---

## 1. System Architecture

```text
threatweaver/
├── configs/                  # Data, model, and continual learning configurations
│   ├── data.yaml
│   ├── model.yaml
│   └── experiments.yaml
├── src/threatweaver/
│   ├── data/                 # Reproducible loaders, temporal splitters, scalers
│   ├── models/               # ResMLP encoder, classifier head, novelty detector
│   ├── learning/             # Bounded replay buffer, 4 selection strategies, trainer
│   ├── evaluation/           # Macro-F1, FPR, catastrophic forgetting, BWT metrics
│   ├── scanner/              # Hardened PE parser, 256-dim feature extractor, scan service, watcher
│   ├── quarantine/           # Safe atomic isolation, XOR encoding, restore, audit logging
│   ├── reporting/            # Local history, JSON/Markdown report generators
│   └── app/                  # Interactive CLI and Windows scanning console
├── scripts/                  # Reproducible benchmark runner
├── tests/                    # Comprehensive unit and integration test suite
├── docs/                     # Research report, threat model, minifilter spec, Nyx roadmap
└── reports/                  # Generated benchmark summaries and scan reports
```

---

## 2. Installation & Quickstart

### Prerequisites
- Windows 10/11 x64 (or Linux/macOS for ML engine and tests)
- Python 3.10+ (Tested on Python 3.12.4)
- [`uv`](https://github.com/astral-sh/uv) (recommended) or standard `pip`

### Setup Virtual Environment
```powershell
# Create virtual environment and install dependencies
uv venv .venv
.venv\Scripts\activate

# Install ThreatWeaver in editable mode
uv pip install -e .
```

---

## 3. Reproducible Commands & Workflows

### A. Launch Apple Minimalist Web UI & Dashboard
Launch the local-first, zero-cloud scanning console with frosted glass aesthetics, live KPI counters, and interactive inspection:
```powershell
.venv\Scripts\threatweaver ui
# Or specify custom port
.venv\Scripts\threatweaver ui --port 8765
```

### B. Run Full Test Suite
```powershell
.venv\Scripts\pytest
```


### B. Continual Learning & Catastrophic Forgetting Benchmark
Compares four replay strategies under identical data, memory, and labeling budgets:
1. *Strategy A: No Replay (Naive Fine-tuning)*
2. *Strategy B: Uniform Random Replay*
3. *Strategy C: Uncertainty-Guided Replay*
4. *Strategy D: Uncertainty + Diversity Replay*

```powershell
.venv\Scripts\python scripts/run_continual_learning_experiment.py
```
This trains the ResMLP neural model, calibrates the novelty detector, saves the trained checkpoint to `artifacts/checkpoints/threatweaver_v1.pt`, and exports full research reports to `reports/continual_learning_summary.md`.

### C. On-Demand File & Directory Scanning
Scan a file or directory with calibrated confidence, evidence attribution, and report export:
```powershell
# Scan directory with checkpoint and export reports
.venv\Scripts\threatweaver scan C:\Path\To\Scan --export-json reports/scan.json --export-md reports/scan.md
```

### D. Safe Reversible Quarantine & Recovery
```powershell
# Quarantine file safely (prompts for confirmation; verifies SHA-256 before/after move)
.venv\Scripts\threatweaver quarantine suspicious_sample.exe

# Dry-run quarantine (validates permissions, paths, and policies without moving)
.venv\Scripts\threatweaver quarantine suspicious_sample.exe --dry-run

# List isolated files in vault
.venv\Scripts\threatweaver list-quarantine

# Restore file from vault
.venv\Scripts\threatweaver restore <quarantine_id>
```

### E. View Scan History
```powershell
.venv\Scripts\threatweaver history
```

---

## 4. Key Security & Safety Guarantees

1. **Zero Untrusted Execution**: Scanned binaries are parsed statically using memory-bounded reads. Code is NEVER executed via Python, PowerShell, emulators, or Wine.
2. **Local-First Privacy**: File contents and hashes are never uploaded to third-party cloud services.
3. **Critical Windows Protection**: The quarantine engine strictly rejects isolation attempts against Windows system directories (`System32`, `SysWOW64`, `explorer.exe`, `ntoskrnl.exe`, etc.).
4. **Symlink / Reparse Point Resistance**: Symlinks are rejected prior to file operations, preventing TOCTOU hijacking.
5. **Neutralized Storage**: Quarantined files are stored with reversible byte XOR masking (`0x5A`) to prevent accidental execution or OS indexing.

---

## 5. Documentation Links

- [Research Report](docs/research_report.md): Methodology, empirical results, and catastrophic forgetting analysis.
- [Endpoint Threat Model](docs/realtime_threat_model.md): Adversary assumptions, attack surfaces, and mitigations.
- [Windows Minifilter Driver Architecture](docs/minifilter_architecture.md): Filter Manager proposal, communication ports, and signing plan.
- [Nyx Operating System Roadmap](docs/nyx_compatibility.md): Capability-based VFS and microkernel integration architecture.
- [Model Card](docs/model_card.md): Model specifications, calibrated thresholds, and failure modes.
- [Dataset Card](docs/dataset_card.md): Feature schema definitions and temporal split protocol.
- [Implementation Plan](plan.md): Phased roadmap tracking and milestone status.
