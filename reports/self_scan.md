# ThreatWeaver Scan Report: `323cbdca`

- **Target Path**: `C:\CODE\ThreatWeaver`
- **Timestamp**: 2026-10-11 19:56:06 - 2026-10-11 19:56:42 (36.24s)
- **Model Version**: ThreatWeaver-v1.0

## Summary

| Metric | Count |
|---|---|
| Total Scanned | 35 |
| Likely Benign | 0 |
| Suspicious | **34** |
| Unfamiliar | **0** |
| Unsupported | 1 |
| Errors | 0 |

## Scanned Files Detail

| File Name | Verdict | Risk Score | SHA-256 | Evidence |
|---|---|---|---|---|
| `cli-32.exe` | **Suspicious** | 100.0% | `32acc1bc5431...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: createprocessa, system |
| `msvcp140-a4c2229bdc2a2a630acdc095b4d86008.dll` | **Suspicious** | 100.0% | `a4c2229bdc2a...` | Anomalous or zeroed PE compilation timestamp; Imports APIs related to dynamic_load: getprocaddress |
| `cli-64.exe` | **Suspicious** | 100.0% | `bbb3de570762...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: createprocessa, system |
| `cli-arm64.exe` | **Suspicious** | 100.0% | `b9a7d08da880...` | Imports APIs related to process_exec: createprocessa, system; Out-of-distribution sample: embedding distance (1.00) exceeds calibrated threshold (0.40). |
| `cli.exe` | **Suspicious** | 100.0% | `32acc1bc5431...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: createprocessa, system |
| `gui-32.exe` | **Suspicious** | 100.0% | `85dae1e95d77...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: createprocessa, system |
| `gui-64.exe` | **Suspicious** | 100.0% | `3471b6140ead...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: createprocessa, system |
| `gui-arm64.exe` | **Suspicious** | 100.0% | `e694f4743405...` | Imports APIs related to process_exec: createprocessa, system; Out-of-distribution sample: embedding distance (1.00) exceeds calibrated threshold (0.40). |
| `gui.exe` | **Suspicious** | 100.0% | `85dae1e95d77...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: createprocessa, system |
| `msvcp140.dll` | **Suspicious** | 100.0% | `7c26614e1d73...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to evasion: gettickcount |
| `libscipy_openblas64_-327b2e0bcffce2882e0dc04cdeb4eaa6.dll` | **Suspicious** | 100.0% | `327b2e0bcffc...` | Section .bss has zero raw size but non-zero virtual size (potential unpack target); Imports APIs related to injection: setthreadcontext |
| `libscipy_openblas-197ee2fc9b4d071f7e048078cac74115.dll` | **Suspicious** | 100.0% | `197ee2fc9b4d...` | Section .bss has zero raw size but non-zero virtual size (potential unpack target); Imports APIs related to injection: setthreadcontext |
| `vcomp140.dll` | **Suspicious** | 100.0% | `95d4ce4a6802...` | Imports APIs related to injection: createremotethread; Imports APIs related to dynamic_load: loadlibraryexw, getprocaddress |
| `c10.dll` | **Suspicious** | 100.0% | `6337930e5825...` | Imports APIs related to dynamic_load: loadlibrarya, getprocaddress; Imports APIs related to evasion: isdebuggerpresent |
| `protoc.exe` | **Suspicious** | 100.0% | `1cbe3f0b2982...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: createprocessw, system |
| `shm.dll` | **Suspicious** | 100.0% | `6a98ce447e49...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: system |
| `libiompstubs5md.dll` | **Suspicious** | 100.0% | `c477314c1b48...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: system |
| `libiomp5md.dll` | **Suspicious** | 100.0% | `de6d18b2dec5...` | Imports APIs related to dynamic_load: loadlibrarya, loadlibraryexa, getprocaddress; Imports APIs related to evasion: isdebuggerpresent |
| `torch_global_deps.dll` | **Suspicious** | 100.0% | `1f0e04909851...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: system |
| `torch.dll` | **Suspicious** | 100.0% | `276fabc18251...` | Imports APIs related to evasion: isdebuggerpresent; Imports APIs related to process_exec: system |
| `uv.dll` | **Suspicious** | 100.0% | `fa569e682fc5...` | Imports APIs related to dynamic_load: loadlibrarya, loadlibraryexw, getprocaddress; Imports APIs related to evasion: isdebuggerpresent |
| `f2py.exe` | **Suspicious** | 100.0% | `caa4a69538c9...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `markdown-it.exe` | **Suspicious** | 100.0% | `3dd89505b7a2...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `isympy.exe` | **Suspicious** | 100.0% | `419cdaf896dd...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `numpy-config.exe` | **Suspicious** | 100.0% | `d1e5fff73e2d...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `py.test.exe` | **Suspicious** | 100.0% | `5c17b3a13efa...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `pygmentize.exe` | **Suspicious** | 100.0% | `44e14ada0816...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `pytest.exe` | **Suspicious** | 100.0% | `5c17b3a13efa...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `pythonw.exe` | **Suspicious** | 100.0% | `5cf904d0e609...` | Imports APIs related to dynamic_load: loadlibraryexw, getprocaddress; Imports APIs related to evasion: isdebuggerpresent |
| `python.exe` | **Suspicious** | 100.0% | `41123879d2e9...` | Imports APIs related to dynamic_load: loadlibraryexw, getprocaddress; Imports APIs related to evasion: isdebuggerpresent |
| `threatweaver.exe` | **Suspicious** | 100.0% | `13f2fff050db...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `torch_python.dll` | **Suspicious** | 100.0% | `5539b241a5ca...` | Imports APIs related to process_exec: system; Out-of-distribution sample: embedding distance (1.00) exceeds calibrated threshold (0.40). |
| `torchfrtrace.exe` | **Suspicious** | 100.0% | `b8f9647b216a...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `torchrun.exe` | **Suspicious** | 100.0% | `eff837db404e...` | Imports APIs related to dynamic_load: getprocaddress; Imports APIs related to process_exec: createprocessa |
| `torch_cpu.dll` | **Unsupported Format** | 0.0% | `420caca3c1b1...` | Validation detail: File size (305887744 bytes) exceeds limit (104857600 bytes) |
