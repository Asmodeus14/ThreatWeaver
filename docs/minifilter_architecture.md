# ThreatWeaver Windows Minifilter Driver Architecture Proposal

> **NOTICE**: ThreatWeaver currently operates using user-mode static inspection and an observational user-mode watcher. This architecture document outlines the formal technical roadmap for the future kernel-mode minifilter driver required for synchronous real-time file blocking.

---

## 1. Filter Manager & Minifilter Model Overview

Windows File System Minifilter Drivers attach to the filesystem stack through the **Filter Manager** (`fltmgr.sys`). The minifilter model provides structured pre-operation and post-operation callbacks for file I/O requests (`IRP_MJ_*`).

```text
+--------------------------------------------------------------+
|             User Mode: ThreatWeaver Scan Service             |
|   - Multi-threaded Static Feature Extractor                  |
|   - ResMLP Deep Learning Classifier & Novelty Detector       |
|   - Quarantine Manager & Policy Decision Engine              |
+--------------------------------------------------------------+
                               ▲  │
      FilterSendMessage (Reply)│  │ FilterGetMessage (Request)
                               │  ▼
+--------------------------------------------------------------+
|         Filter Communication Port (fltmgr.sys IPC)           |
+--------------------------------------------------------------+
                               ▲  │
                               │  ▼
+--------------------------------------------------------------+
|         Kernel Mode: ThreatWeaverFlt.sys (Minifilter)        |
|   - PreOperationCallback: IRP_MJ_CREATE                      |
|   - PostOperationCallback: IRP_MJ_CLEANUP                    |
|   - Stream Context & File Identity Cache                     |
+--------------------------------------------------------------+
                               ▲  │
                               │  ▼
+--------------------------------------------------------------+
|              NTFS / ReFS / FAT32 Filesystem Drivers          |
+--------------------------------------------------------------+
```

---

## 2. Minifilter Callbacks & Interception Protocol

### A. Altitude Allocation
- ThreatWeaver requests a Filter Altitude in the **Anti-Virus (320000 - 329999)** altitude group from Microsoft WHDC.
- Suggested development altitude: `328510`.

### B. Intercepted I/O Operations

1. **`IRP_MJ_CREATE` (Pre-Operation Callback)**:
   - Evaluates file access intent (`FILE_EXECUTE`, `GENERIC_EXECUTE`).
   - For execution requests on PE binaries, checks stream context cache. If verdict is cached as benign, immediately returns `FLT_PREOP_SUCCESS_NO_CALLBACK`.
   - If uncached, requests inspection from user-mode service or pauses dispatch until verification completes.

2. **`IRP_MJ_CLEANUP` (Post-Operation Callback)**:
   - Triggers when a file write handle is closed after modification.
   - Flags file context as dirty to invalidate previous cached scan verdicts.

3. **`IRP_MJ_SET_INFORMATION` (Pre-Operation Callback)**:
   - Monitors file renaming and deletion attempts on quarantined files.

---

## 3. Kernel-User Communication Mechanism

1. **Communication Port Initialization**:
   - Kernel driver initializes port using `FltCreateCommunicationPort(&ServerPort, ...)`.
   - User-mode scanner connects using `FilterConnectCommunicationPort(L"\\ThreatWeaverPort", ...)`.
2. **Synchronous Messaging**:
   - Kernel driver calls `FltSendMessage()` with file path, volume GUID, and process ID.
   - User-mode scanner performs static feature extraction and model inference, then responds with `SCAN_VERDICT_ALLOW` or `SCAN_VERDICT_BLOCK`.
3. **Fail-Safe Timeout**:
   - If user-mode scanner does not respond within `500ms`, the driver defaults to **ALLOW** to prevent system deadlock, logging an uninspected event.

---

## 4. Signing, HVCI & Deployment Requirements

1. **WHQL / Attestation Signing**:
   - Mandatory Extended Validation (EV) Code Signing Certificate.
   - Submission to Microsoft Hardware Developer Program for WHQL attestation signing.
2. **Hypervisor-Protected Code Integrity (HVCI)**:
   - Driver must be compiled with `/INTEGRITYCHECK` and `/guard:cf`.
   - No executable non-paged pool memory allocations (`NonPagedPoolNx`).
3. **Safe Mode Recovery Plan**:
   - In case of boot hangs or blue screens (BSOD), driver service start type is set to `SERVICE_DEMAND_START` during initial testing.
   - Emergency removal script available via Windows Recovery Environment (`WinRE`): `sc.exe config ThreatWeaverFlt start= disabled`.

---

## 5. Isolated Testing & Verification Matrix

- Driver testing MUST take place in an isolated Windows Hyper-V virtual machine with kernel debugging (`kdnet`) enabled.
- Driver Verifier flags enabled:
  - Special Pool
  - Force I/O Checking
  - Deadlock Detection
  - Security Checks
  - Miscellaneous Checks
