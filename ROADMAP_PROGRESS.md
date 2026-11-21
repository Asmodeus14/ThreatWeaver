# ThreatWeaver Roadmap — Progress Tracker

Legend: `[x]` done & verified · `[~]` in progress · `[ ]` not started · `[!]` blocked / needs decision

Defaults chosen (change any time): React + TypeScript frontend · signature bypass removed together with the new model · in-product retraining kept but gated.

## Phase 0 — Repository integrity & honesty
- [x] 0.1 Fix `.gitignore` so `src/threatweaver/data/` is tracked (clean-clone builds) — not yet committed
- [x] 0.2 Remove / label fabricated API & UI data (families, sample details, timeline, edges, KPI cards, tables)
- [x] 0.3 Correct README / model card claims to match real artifacts
- [x] 0.4 Pin dependencies (`pyproject.toml` ranges + exact `requirements.lock.txt`)

## Phase 1 — Critical security
- [x] 1.1 API auth token, Host/Origin checks, no wildcard CORS, JSON-only, body limit, path policy
- [x] 1.2 Stop runtime overwrite of the shipped checkpoint (persist=False default, versioned local bundles)
- [x] 1.3 Ed25519 checkpoint signing, fail-closed loading
- [x] 1.4 Quarantine fixes (symlink check order, exact critical-path prefixes, streaming XOR, manifest validation)
- [x] 1.5 Cache keyed on sha256 + model version; scan `temp`/`cache` folders
- [!] 1.6 Signature as evidence, not ML bypass — deliberately deferred until the Phase 3 model exists (removing the bypass now would expose the current model's ~19% System32 FPR)

## Phase 2 — Feature & evaluation foundation
- [x] 2.1 Deterministic legacy features (replace `hash()`)
- [x] 2.2 `thrember` integration (EMBER2024 v3, 2,568-D) with parity tests
- [~] 2.3 Dataset pipeline — approved: Win64 + .NET train. Pipeline built & tested; download in progress
- [x] 2.4 Sandboxed extraction worker pool (timeouts, memory caps)
- [x] 2.5 Evaluation harness → `eval.json` single source of truth

## Phase 3 — Detection models
- [~] 3.1 LightGBM primary detector, calibrated, FPR-targeted thresholds — .NET model done; Win64 pending download
- [x] 3.2 ResMLP retrained on v3 features (comparison / embeddings) — LightGBM wins; no ensemble
- [x] 3.3 Novelty v2 — Mahalanobis selected; challenge AUROC 0.79, unseen-family 0.59 → kept out of verdicts
- [~] 3.4 Model bundle + verdict policy v2 — wired in, opt-in via `--bundle` until the Win64 model is validated

## Phase 4 — Static analysis & evidence
- [x] 4.1 TreeSHAP grouped explanations
- [x] 4.2 Indicators from raw features
- [x] 4.3 YARA tier
- [x] 4.4 Local hash lists
- [ ] 4.5 capa on demand (optional)

## Phase 5 — Architecture & performance
- [x] 5.1 FastAPI migration (v1 paths preserved)
- [x] 5.2 SQLite storage (scan history; cache already SQLite)
- [x] 5.3 Incremental scan events (cursor endpoint — see log for why not SSE)
- [x] 5.4 App data in `%LOCALAPPDATA%`

## Phase 6 — UI/UX modernization
- [x] 6.1 Vite + React + TS scaffold
- [x] 6.2 Design system
- [x] 6.3 Screen ports per preservation map (legacy UI kept at `/legacy`)
- [x] 6.4 Research dashboards from `eval.json`

## Phase 7 — Advanced (experimental)
- [ ] 7.1 Gated retraining + rollback
- [ ] 7.2 Event-driven watcher
- [ ] 7.3 Opt-in threat intel
- [ ] 7.4 Behavioral telemetry (postponed)

## Phase 8 — Testing, CI, docs, release
- [ ] CI, fuzzing, model regression gate, docs, v0.2 release

## Log
- 0.1: `.gitignore` rule `data/` → `/data/`; `src/threatweaver/data/` now shows as untracked (needs commit).
- 0.2: `server.py` threat-network/families/timeline/sample-details rewritten to real data or `available:false`.
  New `tools/build_family_summary.py` → `artifacts/dataset/family_summary.json` (1,462 real families from 1,086,315 local records).
  UI: fake default graph removed (empty state), KPI cards/chips/ablation/CL tables now loaded from `/api/status`, `/api/timeline`, `/api/embedding-ablation`.
  Found: shipped "ResMLP" has 0 residual blocks (plain MLP); UI ablation table didn't match its own JSON. Tests updated: 85/85 pass; UI JS passes `node --check`.
- 0.3: README feature-status table + measured results with caveats; release notes correction notice; model card rewritten from checkpoint facts.
- 0.4: dependency caps + `desktop`/`build` extras; `requirements.lock.txt` (49 packages, verified with tests).
- 1.1: new `app/security.py` (token, Host/Origin, JSON-only, 1 MiB cap, path policy, quarantine-id check).
  Token is embedded in the served page; UI `fetch` wrapper adds `X-ThreatWeaver-Token`. Wildcard CORS removed; anti-framing headers.
  `threatweaver ui --print-token` for scripts. New `tests/test_server_security.py` (25 tests). 110/110 pass.
  Verified in headless Chrome: UI loads real data; unauthenticated → 401; rebinding Host → 403.
- 1.2: `InferenceEngine.save_state` never overwrites `artifacts/checkpoints/*` or the loaded file; persisted changes become
  `artifacts/models/local/<parent>_local_<UTC>.pt` with lineage in `index.json`. `persist` defaults to False everywhere.
  Note: shipped `threatweaver_v1.pt` already contains 1 user-registered prototype from before this fix (left as-is).
  New `tests/test_checkpoint_protection.py`; 115/115 pass; all 7 shipped checkpoints verified byte-identical.
- 1.3: new `models/signing.py` (Ed25519). Release public key `models/trusted_keys/release_59728268a90fc08a.pub`;
  release PRIVATE key at `%USERPROFILE%\.threatweaver\release_keys\` (outside repo — back it up). Per-install local key
  DPAPI-protected under `%LOCALAPPDATA%\ThreatWeaver\keys`. All 7 shipped checkpoints re-signed (`*.pt.ed25519`) after
  hash verification. `load_checkpoint` is fail-closed (`allow_unsigned` / `THREATWEAVER_ALLOW_UNSIGNED_MODELS=1` for research).
  Legacy `*.pt.sig` HMAC files remain but grant no trust. Added `tools/sign_release_checkpoints.py`, `cryptography` dep,
  package-data + PyInstaller entries, `tests/conftest.py` key isolation. 118/118 pass.
- 1.4: `quarantine/manager.py` rewritten. Reparse points (symlink/junction) rejected on the unresolved path and every parent;
  critical paths = exact `%SystemRoot%\{System32,SysWOW64,WinSxS,Boot,servicing,SystemApps}` prefixes + root files + the vault
  itself; chunked numpy XOR (64 MB file: <16 MB peak); temp-file + fsync + atomic rename; Ed25519-signed manifest
  (tamper / deleted-signature detection); data file must live in the vault; restore destination passes path policy.
  On-disk format unchanged — legacy v0.1 vaults still restore. 10 new tests; 127 pass, 1 skipped (symlink needs admin).
- 1.5: cache rewritten: key = (content SHA-256, engine fingerprint = checkpoint digest + thresholds + prototype count +
  signature-tier flag + `VERDICT_POLICY_VERSION`). Old path+mtime table dropped. File hashed once per scan (also removes the
  second full read on the signature tier). Cache now stores nearest prototype → cached results keep real graph edges.
  Fixed a bug found by the new tests: in-memory hits were not labelled "Cached". Skip list no longer excludes
  temp/tmp/cache/inetcache/installer/package cache. 133 pass ×3 runs, 1 skipped.
- 2.1: `stable_bucket()` (CRC-32) replaces salted `hash()` in `feature_extractor.py` and `ember_extractor.py`.
  Verified: identical vectors across PYTHONHASHSEED 0/1/12345/987 in separate processes; notepad.exe P(mal) now
  0.078864 on every run (was 0.094 vs 0.092). The shipped model was trained with these dims constant, so it stays valid.
  New `tests/test_feature_determinism.py`. 137 pass, 1 skipped.
- 2.2: thrember installed from GitHub pinned to audited commit 0ef753e8 (declarative packaging, no install-time code;
  only network code is explicit dataset download). `signify` pinned <0.8 (0.8+ renamed `SignedPEFile`).
  New `scanner/ember_v3.py` (bounded wrapper, FEATURE_VERSION recorded). Proven: JSON round-trip of raw features ==
  live extraction (training/inference parity by construction); real EMBER2024 records vectorize (2,568-D, finite);
  deterministic across processes; golden vector hashes in `tests/golden/` detect extractor drift.
  Deleted fake `scanner/ember_extractor.py`. Perf note: notepad.exe ≈400 ms (Authenticode parsing) → address in 2.4/5.3.
  `ember` extra in pyproject; lockfile refreshed. 145 pass, 1 skipped.
- 2.3 (in progress): `tools/download_ember2024.py` gained Win64_train (5.85 GB) / Dot_Net_train (0.94 GB) with size +
  SHA-256 verification (HF X-Linked-ETag) before extraction. New `data/ember_v3_dataset.py` + `tools/build_ember_v3_dataset.py`:
  metadata pass (label/PE/file-type filter, exact-sha256 dedupe, byte offsets) → parallel thrember vectorization into float32
  memmaps + Parquet metadata; temporal val = last 8 weeks of train; manifest with source & output SHA-256 and split definition.
  Tested on real records (dedupe, unlabeled, parity with scanner extraction, tamper detection). TLSH near-duplicate audit
  not done yet (needs py-tlsh; O(N·M) cost) — documented limitation.
- 2.5: `evaluation/harness.py` (eval/1 schema): ROC/PR-AUC, TPR@FPR, validation-chosen thresholds applied to test,
  ECE + reliability bins, Brier, histograms, curves, bootstrap CIs, drift, novelty, provenance. Continuity check
  `tools/reproduce_v01_eval.py` reproduces published v0.1 metrics EXACTLY (F1 0.8684, ROC 0.9375, PR 0.9328, DR@1% 0.1805).
  Published novelty AUROC 0.601 came from an undeployed detector (12 protos/class, τ fit on test); shipped detector = 0.563.
  New finding: a 1%-FPR threshold chosen on validation yields 2.06% FPR on test (TPR 0.52).
- 2.4: new `sandboxing/pool.py`: long-lived spawned workers, per-task timeout (kill + respawn), Windows Job Object
  per-process memory cap, crash containment, recycling every 500 tasks, thread-safe. Server and CLI scans use it
  (`isolate_extraction=True`); failures become ANALYSIS_ERROR ("treat as unknown, not benign") and are never cached.
  Found & fixed: `scanner/__init__.py` eagerly imported the inference engine → PyTorch in every parser (3.5 s, hundreds of
  MB); now lazy (PEP 562), worker start ≈0.3 s. Workers run single-threaded (OpenBLAS per-core buffers exceeded the cap).
  Verified: timeout, crash, 700 MB allocation under a 256 MB cap, concurrency, identical verdicts isolated vs in-process.
  165 pass, 1 skipped.
- DATA FINDING: EMBER2024 JSONL files contain every sample twice (line i and i+N/2; copies differ only in `caps`).
  Unique counts are half the record counts (e.g. ".NET test 120,000" = 60,000 unique files). v3 pipeline dedupes by
  SHA-256; family summary + UI now count unique samples. Phase-0 family counts were double-counted (fixed; rerun pending).
- 2.3: full .NET build — train 220,000 / val 40,000 / test 59,953 / challenge 829 unique samples, 0 failures, 94 s.
- 3.1 (.NET): `artifacts/models/lgbm-v3-dotnet` (500 trees, 148 s train). Official test split, val-chosen thresholds:
  ROC-AUC 0.9979, TPR@1%FPR 0.955 (v0.1: 0.18); τ_high → 81.6% TPR at 0.057% FPR; τ_low → 95.5% TPR at 0.99% FPR;
  evasive challenge (.NET) 79.5% caught at τ_low; 0.016 ms/sample model time. Release-signed; opt-in only (.NET-trained).
- 3.4: `core/policy.py` (policy-v2, exhaustive truth-table tests), `models/bundle.py` (fail-closed signed LightGBM loader),
  engine `_analyze_with_bundle` (single sandboxed parse → v3 vector + indicators; signature = evidence → this is 1.6 on the
  v2 path). New verdicts Known/Likely Malicious + Trusted Signer through reports, CLI, server, UI. `--bundle` option.
  On System32 the .NET-only model gives 0 Likely Malicious but 16% Suspicious → native-binary training data required.
  Large files: thrember string features ≈0.75 s/MB (87 MB file → 65 s); timeout now 15 s + 1 s/MB (cap 180 s).
  Files > 100 MB report the real size-limit reason. 181 pass, 1 skipped.
- 4.1: exact TreeSHAP (LightGBM pred_contrib) grouped into 12 thrember families; readable "Model attribution" evidence;
  `/api/sample-details` returns real attribution (replaces fabricated 88/92/75 bars).
- 3.2: residual MLP (3 real residual blocks, 64-D emb.) — test TPR@1%/0.1% FPR 0.908/0.646 vs LightGBM 0.955/0.835
  (non-overlapping 95% CIs); mean ensemble 0.946/0.819 → worse than LightGBM alone → NOT adopted.
- 3.3: novelty selected on val = Mahalanobis: test unseen-family AUROC 0.591 (CI 0.566–0.612), challenge vs benign 0.79
  (shipped: 0.563); kNN 0.39 on challenge (worse than chance). Novelty stays out of verdicts until it improves.
- 4.3/4.4: `detectors/known_bad.py` — offline hash lists (+labels), allowlist, YARA (compile cache, timeout); match →
  Known Malicious naming the rule even at low model score; part of the cache fingerprint. No third-party rules bundled.
- 4.2: `detectors/indicators.py` from thrember raw (packers, W^X, unpack targets, entry section, overlays, API combos,
  signature anomalies, parser warnings). Tuned on 148 signed System32 files: dropped "future timestamp" (fired on 55% —
  reproducible builds) and 1–2 parser warnings (17%). v2 path now parses each file once.
- 5.4: `core/paths.py` — vault, cache, history, local models, keys, rules under `%LOCALAPPDATA%\ThreatWeaver`
  (THREATWEAVER_HOME override); resources from install root (works frozen). Real run migrated the v0.1 vault (copy +
  SHA-256 verify, legacy kept with MIGRATED.txt). Tests use a throwaway home.
- 5.2: SQLite (WAL) scan history, same API/shape + `search_results()`; imported all 170 legacy scans once.
- 5.3: `/api/scan/events?since=&seq=` cursor endpoint (≤250 new results/poll; UI renders latest 500). Not SSE because
  EventSource cannot send the auth header (token in URL would leak to logs/history).
- 5.1: FastAPI app (`app/api.py`) delegating to `ApiCore` (the existing handler logic run socket-free) → one
  implementation, identical v1 behaviour; OpenAPI at `/api/openapi.json`; guard as middleware; uvicorn is the default
  runtime, stdlib fallback. Found & fixed: Windows spawn re-imports the launcher → added `freeze_support()` to CLI and
  desktop entry points (otherwise a PyInstaller build would relaunch itself in every parsing worker). 207 pass.
- 6: `frontend/` (Vite, React 18, strict TS, IBM Plex bundled offline, hand-written SVG charts instead of ECharts:
  207 KB JS / 64 KB gzip). Served at `/` (token injected); classic UI at `/legacy`. Signature element: calibrated verdict
  scale with the active detector's real thresholds. Preservation map: KPI facts, threat web (new canvas; real fs_items),
  scan results (incremental), families, ablation table, continual-learning timeline/table (+ R-matrix heatmap), quarantine,
  history, learning queue/prototypes, settings — all from real API data. New: Detections + detail drawer (policy reason,
  TreeSHAP attribution, indicators, actions), Model performance (log-FPR ROC, PR, histogram, reliability, drift,
  operating points, CIs). 3D "neural studio" (illustrative animation) remains in `/legacy` only. Reviewed via headless-
  Chrome screenshots in both themes; fixed overlapping threshold labels, duplicate rows, clipped graph labels, PR axis.
  Vitest + server tests; 210 Python tests pass.
