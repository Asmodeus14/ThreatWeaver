# Changelog

All notable changes to ThreatWeaver. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — 0.2.0

### Security
- Local API requires a per-session token; Host allow-list, Origin checks, no wildcard CORS, JSON-only bodies, 1 MiB cap and a path policy close cross-site and DNS-rebinding control of quarantine, restore, settings and learning endpoints.
- Ed25519 model signing with fail-closed loading replaces the HMAC whose key was in the source.
- The shipped model can no longer be overwritten at runtime; adaptations are versioned.
- Quarantine: symlink/junction checks before resolution, exact protected-path prefixes (a folder named `system32` no longer blocks quarantine), streaming I/O, signed manifest, validated restores.
- Result cache keyed on content hash and engine fingerprint (was path + timestamp).
- PE parsing runs in isolated worker processes with timeouts and memory caps.
- Full scans no longer skip temp, browser-cache, download and installer-cache folders.

### Added
- LightGBM detector on EMBER2024 feature version 3 (official `thrember` extractor), trained on Win64 + .NET, calibrated, with thresholds for 1% and 0.1% false-positive rates chosen on temporal validation data. It is the default detector; `--legacy` selects the v0.1 model.
- Verdict policy v2 with *Known Malicious*, *Likely Malicious* and *Trusted Signer*; signatures are evidence, not a bypass.
- Per-file explanations (exact TreeSHAP grouped into feature families) and static indicators tuned against signed Windows binaries.
- Known-bad tier: local SHA-256 hash lists, allowlist and user-supplied YARA rules.
- Opt-in MalwareBazaar hash lookups (hash only, off by default).
- Observational folder watcher using file-system events.
- Gated retraining with analyst feedback and a model regression gate.
- Evaluation harness (`eval.json`, bootstrap CIs, drift) and a continuity check reproducing the v0.1 numbers exactly.
- New React + TypeScript interface (classic UI kept at `/legacy`), FastAPI server with an OpenAPI contract, SQLite scan history, per-user app-data directory.
- CI workflow, malformed-PE fuzz tests.

### Fixed
- The data package was excluded by `.gitignore`, so a clean clone did not build.
- Feature vectors used Python's per-process `hash()`, making scores differ between runs.
- Training and inference used different feature definitions (179 of 256 training features were constant).
- UI and API displayed fabricated data (invented families, similarity edges, attribution scores and timeline).
- Documentation metrics that could not be traced to the shipped model; the "0% System32 FPR" figure reflected the signature bypass.
- Dataset family counts double-counted samples (each appears twice in the EMBER2024 files); counts are now unique.

### Removed
- `scanner/ember_extractor.py`, which claimed EMBER compatibility but was an approximation.

## [0.1.0] — 2026-10-25
Initial research prototype. See `release_notes.md` (with its 2026-11-21 correction notice).
