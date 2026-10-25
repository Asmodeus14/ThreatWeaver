# ThreatWeaver Synthetic PE Sample Vault

This directory contains syntactically valid Portable Executable (PE) binaries generated strictly for safe, zero-execution static analysis testing:

- **benign_utility.exe**: Minimal 64-bit GUI executable with standard DEP/NX protections.
- **benign_helper.dll**: Minimal 64-bit shared library.
- **suspicious_packed.exe**: 32-bit executable featuring a writable-and-executable (`W+X`) `.upx0` section (triggers neural suspicion indicators).
- **novelty_stub.exe**: High-entropy section data designed to evaluate the ResMLP distance and novelty/out-of-distribution detector.

> None of these files contain executable malware payloads or malicious code.
