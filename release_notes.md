# ThreatWeaver v0.1.0 — Initial Release

ThreatWeaver is a defensive cybersecurity research platform and next-generation Windows antivirus prototype engineered for static Portable Executable (PE) inspection without execution.

Combining deep neural representation learning, temperature-calibrated uncertainty estimation, out-of-distribution novelty detection, and catastrophic-forgetting-resistant continual adaptation, ThreatWeaver delivers robust binary triage with zero dynamic execution risks.

---

## What's Included in v0.1.0

### 1. Zero-Execution Static Triage Engine
- **Non-Executing Inspection:** All binary evaluation is strictly static. Binaries are parsed as raw byte streams and structured PE headers (`pefile`). Code is never executed, injected, or emulated.
- **Authenticode Signature Verification:** Valid Microsoft and trusted vendor certificates bypass deep inference for sub-millisecond triage.
- **SQLite SHA-256 Hash Caching:** Fast local cache (`.threatweaver/hash_cache.db`) delivers deterministic verdicts in under 4ms.

### 2. Deep Learning Representation & Calibration
- **128-D ResMLP Encoder:** 256 structural and statistical PE features projected into a 128-dimensional L2-normalized unit hypersphere.
- **Platt Temperature Calibration:** Post-hoc calibration ($T = 1.11$) achieves an Expected Calibration Error ($ECE = 0.0147$).
- **Cosine Novelty Gate:** Isolates out-of-distribution zero-day threats by measuring angular distance to known cluster prototypes.

### 3. Dual Continual Adaptation (No Catastrophic Forgetting)
- **Option A (Instant Zero-Risk Prototype Registration):** Registers a sample's 128-D embedding directly as a prototype centroid without altering model weights.
- **Option B (Uncertainty + Diversity Replay Fine-Tuning):** Retrains weights using active learning alongside EMBER baseline replays to preserve historical classification accuracy.

### 4. Apple-Inspired Minimalist Web UI & Desktop Packaging
- **Standalone Windows Distribution:** Pre-compiled self-contained Windows application (`ThreatWeaver.exe`) requiring no external Python installation.
- **Interactive UI:** Frosted glass aesthetic with live KPI telemetry, scan results table, 3D Threat Web cluster visualization, neural trace studio, and quarantine management.

---

## Benchmark Performance

| Metric | Result | Benchmark |
| :--- | :---: | :--- |
| **Validation Macro F1** | **0.9089** | > 0.8500 |
| **ROC-AUC** | **0.9592** | > 0.9200 |
| **Expected Calibration Error (ECE)** | **0.0147** | < 0.0500 |
| **System32 False Positive Rate** | **0.00%** | Zero false alarms on core Windows binaries |
| **Cached Scan Latency** | **< 4 ms** | Real-time cache throughput |
| **Automated Tests** | **84 / 84** | 100% test pass rate |

---

## Getting Started

### Using the Standalone Windows Release (Recommended)
1. Download `ThreatWeaver-v0.1.0-win64.zip` from the release assets below.
2. Extract the archive.
3. Double-click `ThreatWeaver.bat` (or run `ThreatWeaver.exe`).
4. The application starts the local server and automatically opens the dashboard in your default browser at `http://127.0.0.1:8765`.

### Using Python / CLI
```powershell
git clone https://github.com/Asmodeus14/ThreatWeaver.git
cd ThreatWeaver
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .

# Launch Web UI
threatweaver ui

# Run on-demand scan
threatweaver scan samples/ --export-json reports/scan.json
```

---

## Assets
- `ThreatWeaver-v0.1.0-win64.zip`: Standalone Windows x64 binary distribution.
