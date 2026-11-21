# Security Policy

## Supported Versions

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 0.2.x   | :white_check_mark: | Hardened release (see below) |
| 0.1.x   | :x:                | Contains the vulnerabilities fixed in 0.2 — upgrade |

ThreatWeaver is a research prototype for static triage of Windows PE files. It is not an antivirus replacement and provides no real-time protection.

---

## Threat model

ThreatWeaver processes hostile input (untrusted executables) and exposes a local HTTP API. It is designed so that neither a malicious file nor a malicious web page can turn it against the user.

| Threat | Mitigation (0.2) |
| :--- | :--- |
| A web page in the user's browser drives the local API (CSRF / DNS rebinding) to quarantine, restore or reconfigure | Per-session token required on every `/api` request in a custom header; Host allow-list; foreign `Origin` rejected; no CORS; JSON-only bodies; 1 MiB body cap (`app/security.py`) |
| Path tricks in API input (device paths, UNC shares, NTFS alternate data streams) | Path policy rejects `\\.\`, `\\?\`, UNC and `file:stream` forms before any file access |
| A malformed or hostile PE hangs or crashes the parser | Parsing runs in isolated worker processes with a per-file timeout and a Windows Job Object memory cap; a timeout or crash becomes an *Analysis Error* verdict ("treat as unknown, not benign"); seeded fuzz tests cover truncated and corrupted headers |
| Tampered or substituted model files | Ed25519 signatures: shipped models are release-signed (public key in `src/threatweaver/models/trusted_keys/`); locally adapted models are signed with a per-install key protected by Windows DPAPI. Unsigned, tampered or unknown-key models are refused. PyTorch checkpoints load with `weights_only=True`; LightGBM models load from text (no pickle) |
| Runtime learning overwrites the shipped model | The shipped and loaded checkpoints are read-only; adaptations become new versioned files; retraining is accepted only through a regression gate |
| Cached "benign" verdict reused for a swapped file | The cache is keyed on the file's SHA-256 and an engine fingerprint (model, thresholds, rules, policy version) — not on path or timestamp |
| Signed malware (stolen or abused certificates) | A valid signature is evidence only; it never suppresses a high model score (v2 detector). The legacy model path still skips the model for signed files until the v2 detector is the default |
| Quarantine abuse (symlinks, junctions, protected OS files, tampered manifest) | Reparse points rejected on the unresolved path and every parent; protected `%SystemRoot%` locations matched by exact prefix; the vault manifest is signed; restores verify the data-file location, destination path and SHA-256 |
| Leaking user data to third parties | Fully offline by default. Optional MalwareBazaar lookups send only a file's SHA-256, require an explicit opt-in and an API key (stored with DPAPI) |

Known limitations:
- Quarantine uses a constant XOR mask so stored files cannot run by accident. It is neutralisation, not encryption.
- YARA rules run in the main process (libyara, with a per-file timeout); move them into the sandbox if you load untrusted rule sets.
- The bundled release signing key belongs to the maintainer; forks must generate their own (`tools/sign_release_checkpoints.py --generate-key`).

---

## Safe handling of malware samples

- ThreatWeaver never executes, loads or emulates the files it inspects.
- Still, analyse live malware only inside an isolated virtual machine.
- Do not run ThreatWeaver elevated unless you need to scan protected directories.
- The files in `samples/` are harmless synthetic stubs for testing.

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
