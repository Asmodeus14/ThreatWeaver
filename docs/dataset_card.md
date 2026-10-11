# ThreatWeaver Dataset Card

## 1. Dataset Provenance & Scope

- **Benchmark Name**: ThreatWeaver Static PE Benchmark Dataset (v1.0)
- **Primary Schema**: Schema v1.0 (256 floating-point static features).
- **External Dataset Compatibility**: Compatible with EMBER2024 / SOREL-20M feature spaces via dimensionality projection and JSONL streaming loaders.
- **Licensing**: Apache 2.0 (ThreatWeaver synthetic benchmark suite); public datasets used according to their respective upstream licenses.

---

## 2. Feature Schema Definition (256 Dimensions)

| Dimension Range | Feature Category | Description |
|---|---|---|
| **0 - 31** | Header & Structural | File size (log scaled), machine type (x86/x64/ARM), number of sections, timestamp anomaly flag, characteristics flags, subsystem (GUI/Console/Native), ASLR/DEP/HighEntropyVA flags, entry point RVA ratio, number of imports/exports. |
| **32 - 95** | Section-Level Statistics | Overall Shannon entropy (0-8 bits), max/mean/min section entropies, executable section counts, writable section counts, W^X violations, 0-raw size section count, standard section presence (.text, .data, .rdata, .rsrc, .reloc), top 16 section entropy vector. |
| **96 - 159** | Import & API Categorization | Suspicious API categories (process injection, dynamic loading, anti-debugging evasion, persistence, hooking, networking, process execution, crypto) presence flags and log counts; hash projections of imported DLL names and function symbols. |
| **160 - 255** | Byte Histogram & Strings | 64-bin compressed byte frequency histogram, printable ASCII character density, suspicious string regex indicators (PowerShell, cmd, URL, IP pattern, registry run keys, base64 markers), sliding-window entropy quantiles. |

---

## 3. Temporal Split Protocol & Leakage Prevention

- **Temporal Batching**: Chronological ordering by sample timestamp ($T_1 \dots T_5$).
- **Look-Ahead Leakage Guarantee**: Samples from past time periods ($T_i$) never observe samples from future time periods ($T_j, j > i$).
- **Preprocessing Isolation**: Feature normalization scalers (mean and standard deviation) are strictly fitted on training splits only and frozen during inference.

---

## 4. EMBER Integration & Harmonization Pipeline

- **EMBER Specification**: Supports EMBER 2018 and EMBER 2024 raw datasets (2,381 raw dimensions).
- **Streaming Ingestion**: `EMBERDatasetLoader` processes `train_features.jsonl` chunk-by-chunk without loading multi-gigabyte files into system RAM.
- **Label Sanitization**: Samples with `label == -1` (unlabeled) are isolated/dropped to ensure supervised ground truth integrity.
- **Chronological Partitions**: Partitions data chronologically according to the `appeared` month tag (`2018-01` through `2018-12`) to evaluate temporal drift.
- **Harmonized Projection vs. Native Extractor**:
  - **Harmonized Mode (256 dims)**: Compresses EMBER's 256 byte histogram into 64 grouped bins and projects section, header, and import features directly into ThreatWeaver's Schema v1.0.
  - **Native Mode (2,381 dims)**: Preserves the complete 2381-dimensional vector, paired with `EMBERFeatureExtractor` which extracts identical 2381-dim vectors from live `.exe` files on Windows.

