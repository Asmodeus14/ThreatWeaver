# ThreatWeaver Data Integrity & Leakage Prevention Protocol

## 1. Dataset Provenance & Real EMBER2024 Manifest

ThreatWeaver utilizes verified, authentic partitions of the **EMBER2024** benchmark dataset acquired directly from the official upstream repository (`joyce8/EMBER2024`, Apache-2.0 license).

### Local Verified Partitions

| Partition | Samples | Benign | Malicious | Format | Time Span |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `challenge/` | 6,315 | 0 | 6,315 | PE (Win32, Win64, .NET) | 2023-09 to 2024-12 |
| `Dot_Net_test/` | 120,000 | 60,000 | 60,000 | Windows PE (.NET Assemblies) | 2023-09 to 2024-12 |
| **Total** | **126,315** | **60,000** | **66,315** | **Windows PE Executables** | **2023-09 to 2024-12** |

- **Storage Location**: `data/ember2024/`
- **Total Uncompressed Disk Size**: 1,163.9 MB (76 JSONL partition files)
- **Corruption Audit**: `0` corrupt records across all 126,315 samples.
- **Machine Types**: Win32 (x86), Win64 (AMD64), and .NET CLI PE binaries.
- **Verification Tool**: CLI command `threatweaver dataset verify` produces and validates `artifacts/dataset/ember2024_manifest.json`.

---

## 2. Mathematical Anti-Leakage Safeguards

Data leakage between training, validation, and evaluation partitions distorts empirical metrics and causes catastrophic real-world degradation. ThreatWeaver enforces strict architectural boundaries:

### 2.1 Feature Scaling Isolation
Standardization parameters ($\mu$ and $\sigma$) are computed **strictly on the training split $X_{\text{train}}$**:

$$\mu_{\text{train}} = \frac{1}{N_{\text{train}}} \sum_{i=1}^{N_{\text{train}}} x_i, \quad \sigma_{\text{train}} = \sqrt{\frac{1}{N_{\text{train}}} \sum_{i=1}^{N_{\text{train}}} (x_i - \mu_{\text{train}})^2 + \epsilon}$$

Any validation set $X_{\text{val}}$, test set $X_{\text{test}}$, or real-time inference sample $x$ is normalized using the frozen $\mu_{\text{train}}$ and $\sigma_{\text{train}}$:

$$x_{\text{scaled}} = \frac{x - \mu_{\text{train}}}{\sigma_{\text{train}}}$$

The scaler's state is serialized into checkpoint metadata and NEVER refit on evaluation data.

### 2.2 Novelty Prototype Isolation
In ThreatWeaver, prototype vectors $\{p_k\}_{k=1}^K$ for cosine novelty and out-of-distribution (OOD) scoring are extracted **exclusively from the training partition**:

$$p_k = \frac{\bar{e}_k}{\|\bar{e}_k\|_2}, \quad \text{where } \bar{e}_k = \frac{1}{|C_k|} \sum_{i \in C_k \cap \text{train}} e_i$$

Test and validation samples never contribute to prototype centroids.

### 2.3 Chronological & Temporal Integrity
Malware evolves non-stationarily over time (concept drift). Evaluating models on randomly split data leads to severe temporal lookahead leakage, where future malware variants leak into the past.
- The `TemporalSplitter` sorts samples strictly by their real-world submission timestamp:
  
  $$\text{Sort by: } t_i = \text{record.first\_submission\_date}$$

- The chronologically earliest samples form $T_{\text{train}}$ ($t < T_1$), intermediate samples form $T_{\text{val}}$, and chronologically future samples form $T_{\text{test}}$ ($t > T_2$).
- Zero-overlap is asserted programmatically across index sets:
  
  $$\mathcal{I}_{\text{train}} \cap \mathcal{I}_{\text{val}} = \emptyset, \quad \mathcal{I}_{\text{val}} \cap \mathcal{I}_{\text{test}} = \emptyset, \quad \mathcal{I}_{\text{train}} \cap \mathcal{I}_{\text{test}} = \emptyset$$

---

## 3. Zero-Execution PE Feature Harmonization

ThreatWeaver operates under a strict **Zero-Execution Defensive Guarantee**.
Features are extracted without loading binaries into memory space, resolving imports dynamically, or executing process threads:

1. **Header & Machine Characteristics** (dims 0..31): File size logarithm, machine architecture flags (x86, x64), subsystem (GUI, CUI), DLL security flags (DEP/NX, ASLR/DynamicBase).
2. **Section Topography & Entropies** (dims 32..95): Section count, mean, min, and max Shannon section entropy ($H = -\sum p_i \log_2 p_i$), section virtual vs. raw size ratios.
3. **Byte Histogram & Byte Distribution** (dims 160..223): 64-bin normalized byte frequency distribution capturing packing and obfuscation patterns.
4. **Strings & Linguistic Density** (dims 224..255): Printable ASCII ratio, average string length, printable density.

All 256 dimensions are validated for finite numerical bounds (`nan_to_num(X, nan=0.0, posinf=1.0, neginf=-1.0)`).
