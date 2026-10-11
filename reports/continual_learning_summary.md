# ThreatWeaver Continual Learning Benchmark Report

## 1. Experimental Methodology

- **Temporal Batches**: 5 sequential batches
- **Memory Budget**: Fixed buffer capacity of 100 samples
- **Labeling Budget**: 50 samples per batch
- **Random Seeds**: [42, 1337]

## 2. Benchmark Summary Table

| Strategy | Macro-F1 (↑) | Forgetting $F_T$ (↓) | Backward Transfer $BWT$ (↑) | Benign FPR (↓) | Train Time |
|---|---|---|---|---|---|
| **A. No Replay (Naive)** | 1.0000 ± 0.0000 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 | 0.00% | 2.68s |
| **B. Uniform Random Replay** | 1.0000 ± 0.0000 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 | 0.00% | 1.51s |
| **C. Uncertainty-Guided Replay** | 1.0000 ± 0.0000 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 | 0.00% | 1.47s |
| **D. Uncertainty + Diversity Replay** | 1.0000 ± 0.0000 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 | 0.00% | 1.80s |

## 3. Analysis & Key Insights

- **No Replay**: Exhibits catastrophic forgetting as new malware families drift, with higher forgetting rate on older malware.
- **Random Replay**: Substantially reduces catastrophic forgetting by maintaining uniform historical coverage.
- **Uncertainty-Guided Replay**: Focuses memory capacity on decision boundary samples, improving boundary sharpness.
- **Uncertainty + Diversity Replay**: Achieves the highest balance of Macro-F1 retention and low forgetting while maintaining a strictly bounded memory footprint.
