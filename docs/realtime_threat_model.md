# ThreatWeaver Real-Time Endpoint Protection Threat Model

## 1. System Overview & Scope

ThreatWeaver is an AI-powered malware research engine and defensive antivirus prototype. This threat model evaluates the endpoint attack surface, security assumptions, adversary capabilities, and defense mechanisms for ThreatWeaver's static scanning, observational monitoring, and future kernel minifilter components.

---

## 2. Security Assumptions

1. **Host Integrity**: The initial installation occurs on a clean or non-compromised Windows endpoint. If ring-0 kernel rootkits already control the host, software-level antivirus guarantees cannot be upheld.
2. **Untrusted Input**: Every file presented to the scanner, whether via on-demand scan or real-time file event, is treated as adversarial and potentially malicious.
3. **No Execution Guarantee**: ThreatWeaver must NEVER execute, emulate, launch, or dynamically load untrusted binaries during inspection.
4. **Coexistence**: ThreatWeaver must never disable, conflict with, or undermine Microsoft Defender or third-party security controls.

---

## 3. Adversary Profile & Attack Vectors

| Attack Vector | Adversary Objective | ThreatWeaver Mitigation |
|---|---|---|
| **PE Parser Exploitation** | Crash scanner process or achieve RCE via malformed PE headers, integer overflows, or recursive directories. | Defensive pre-validation (`validate_file_pre_parse`), bounded memory reading (max 100MB), strict bounds checking, defensive exception wrapping, no unsafe pointer manipulation. |
| **Quarantine Path Traversal** | Trick quarantine into deleting or overwriting sensitive system files using directory traversal (`..\..\Windows\System32`). | Absolute path resolution (`Path.resolve()`), path traversal rejection, critical system directory blacklist (`CRITICAL_WINDOWS_PATHS`), and mandatory human confirmation. |
| **Symlink / Reparse Point Race** | Replace scanned file with symlink pointing to legitimate document before quarantine move (TOCTOU). | Explicit `is_symlink()` check, pre- and post-move SHA-256 hash verification, atomic moves where supported. |
| **Model Poisoning / Replay Buffer Poisoning** | Feed adversarial samples into the continual learning replay buffer to degrade model accuracy. | Buffer admission restricted to verified, appropriately labeled examples; budget limits per batch; uncertainty+diversity filtering. |
| **Event Storm Denial of Service** | Flood the filesystem with millions of micro-file write events to starve the scanner of CPU/RAM. | Observational watcher with bounded event queue (1,000 max), sliding-window deduplication filter (2.0s), and event drop telemetry. |
| **Adversarial Perturbation / Evasion** | Pad sections or inject benign API strings into malware to lower classifier risk score. | Multi-evidence defense: explicit section entropy analysis, W^X permission violation checks, and novelty detection that flags strange perturbations as "Unfamiliar / Out-of-Distribution" rather than benign. |

---

## 4. Privacy & Data Handling Guarantees

- **Local-First Processing**: All feature extraction, model inference, and quarantine isolation occur 100% locally on the host machine.
- **Zero Cloud Upload by Default**: Scanned files, hashes, and extracted features are never transmitted to external services without explicit user configuration.
- **Sanitized Reports**: Exported JSON/Markdown reports contain file paths, hashes, and evidence summaries, but never raw executable binary contents.
