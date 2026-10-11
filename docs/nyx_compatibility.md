# ThreatWeaver Architecture: Nyx Operating System Compatibility Roadmap

## 1. Architectural Philosophy

ThreatWeaver is designed from the ground up as a **portable, modular, local-first malware research engine**. While its initial endpoint scanner targets Windows PE executables, its core representations—feature schema versioning, ResMLP neural encoders, continual learning replay memory, and embedding-based novelty detection—are completely decoupled from operating system internals.

This document describes the architectural roadmap for porting and integrating ThreatWeaver into the user's **Nyx operating system**.

---

## 2. Decoupled Core Layering

```text
+-------------------------------------------------------------------------+
|                       ThreatWeaver Core ML Engine                       |
|   (PyTorch / C++ / ONNX Runtime - Feature Normalization, ResMLP,        |
|    Novelty Detector, Calibrated Confidence, Continual Replay Buffer)    |
+-------------------------------------------------------------------------+
                                     │
           Standardized Feature Vector (256-dim Schema Interface)
                                     ▼
+-------------------------------------------------------------------------+
|                  OS & Format-Agnostic Static Parser API                 |
+-------------------------------------------------------------------------+
                  │                                     │
                  ▼                                     ▼
+-----------------------------------+ +-----------------------------------+
|         Windows Subsystem         | |           Nyx Subsystem           |
|  - PE32/PE32+ Header Parser       | |  - Nyx ELF / Native Executable    |
|  - Win32 API Call Mapping         | |  - Nyx Capability & Syscall Map   |
|  - fltmgr.sys Minifilter Driver   | |  - Nyx Microkernel IPC Daemon     |
|  - ReadDirectoryChangesW Watcher  | |  - Nyx VFS Interception Hooks     |
+-----------------------------------+ +-----------------------------------+
```

---

## 3. Nyx OS Integration Strategy

### A. Binary Format & Feature Schema Adaptation
- On Nyx, the file parsing layer (`threatweaver.scanner.pe_parser`) will be paired with a `threatweaver.scanner.nyx_parser`.
- The parser extracts:
  1. Header metadata: target architecture, entry points, segment tables, relocation tables.
  2. Section-level entropy and W^X violations (identifying segments marked readable, writable, and executable simultaneously).
  3. Dynamic symbol linkages and capability requests.
  4. Byte histograms and entropy quantiles (which are 100% portable across all operating systems).
- Feature Schema v2.0 will map Nyx-specific syscalls and capabilities into the 256-dimensional input vector.

### B. Microkernel / Capability-Based Interception
- In a modern capability-based OS such as Nyx, security enforcement does not require monolithic kernel hooks.
- Instead, the Nyx Virtual File System (VFS) service or Loader server communicates via high-performance microkernel IPC endpoints with an isolated, unprivileged `threatweaver-daemon`.
- The `threatweaver-daemon` receives read-only file descriptors or shared memory buffers containing the binary payload, performs static inference, and responds with capability grants or execution denial.

### C. Resource Efficiency & Zero-Copy Execution
- High performance on Nyx is achieved by mapping the executable's header pages into the analysis daemon's address space via shared physical memory pages.
- Feature extraction completes in < 5ms without copying large binary data.
