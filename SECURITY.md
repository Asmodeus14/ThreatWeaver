# Security Policy

## Supported Versions

ThreatWeaver is actively maintained as an open-source defensive cybersecurity research platform and next-generation antivirus prototype. Security updates and patches are provided for the following releases:

| Version | Supported          | Status         |
| ------- | ------------------ | -------------- |
| 0.1.x   | :white_check_mark: | Current Active |
| < 0.1.0 | :x:                | Deprecated     |

---

## Defensive Architecture & Core Security Guarantees

ThreatWeaver is engineered from the ground up to analyze potentially malicious, packed, and hostile Portable Executable (PE) binaries without exposing the host operating system to compromise:

### 1. Zero-Execution Static Analysis
- **Non-Executing Inspection:** All binary evaluation is strictly static. Binaries are read strictly as raw byte streams and structured PE headers (`pefile`).
- **No Dynamic Sandboxing:** Binaries are never executed, injected, or loaded as runtime libraries (`LoadLibrary` is never invoked on inspected targets).
- **Safe Parsing Protections:** Header parsing implements strict size limits, recursion limits, and exception traps to mitigate PE parsing denial-of-service or memory corruption vectors.

### 2. Checkpoint Integrity & Deserialization Defense
- **HMAC-SHA256 Signature Verification:** Model checkpoints (`.pt`) are paired with cryptographic HMAC-SHA256 signatures (`.sig`). Checkpoints failing signature verification are rejected immediately before deserialization.
- **`weights_only=True` Safe Deserialization:** PyTorch model weights are deserialized strictly using `weights_only=True`, blocking Python pickle-based Remote Code Execution (RCE) gadgets and arbitrary object instantiation.

### 3. Reversible Isolation Quarantine
- Quarantined binaries are neutralized using a reversible byte-inversion XOR envelope before storage in `.threatweaver/quarantine/`.
- Quarantined files are rendered inert and unexecutable by the host operating system until explicitly restored by the user.

### 4. Deterministic Hash Caching
- SHA-256 digests are computed for all evaluated binaries and indexed in a local SQLite database (`.threatweaver/hash_cache.db`).
- Cache lookups bypass repetitive parsing while guaranteeing that any byte-level mutation automatically triggers a complete re-evaluation.

---

## Safe Handling of Malware Binaries

When using ThreatWeaver to evaluate live malware or untrusted executables:
- Always operate within an isolated virtual machine or dedicated analysis sandbox.
- Do not run ThreatWeaver as an elevated user (`Administrator` or `root`) unless scanning system-protected directories is specifically required.
- Do not execute sample files in `samples/` or test directories outside an isolated lab environment.

---

## Reporting Security Vulnerabilities

We take the security of ThreatWeaver seriously. If you discover a security vulnerability or bypass in ThreatWeaver:

1. **Do not open a public issue.**
2. Send a detailed vulnerability report via email to **Abhay Singh** at:  
   `singhabhay3145@gmail.com`
3. Please include:
   - A description of the vulnerability and attack vector.
   - Proof of Concept (PoC) code or reproducible steps.
   - Any proposed remediation or mitigation.

### Response Timeline
- **Initial Acknowledgment:** Within 48 hours of receipt.
- **Triage & Assessment:** Within 5 business days.
- **Coordinated Disclosure:** We aim to release patches promptly before public disclosure.
