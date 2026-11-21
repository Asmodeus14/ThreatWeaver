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
- [ ] 2.2 `thrember` integration (EMBER2024 v3, 2,568-D) with parity tests
- [!] 2.3 Dataset pipeline — needs approval for EMBER2024 train-partition download (~75–100 GB)
- [ ] 2.4 Sandboxed extraction worker pool (timeouts, memory caps)
- [ ] 2.5 Evaluation harness → `eval.json` single source of truth

## Phase 3 — Detection models
- [ ] 3.1 LightGBM primary detector, calibrated, FPR-targeted thresholds
- [ ] 3.2 ResMLP retrained on v3 features (comparison / embeddings)
- [ ] 3.3 Novelty v2 (kNN reference bank)
- [ ] 3.4 Model bundle + verdict policy v2

## Phase 4 — Static analysis & evidence
- [ ] 4.1 TreeSHAP grouped explanations
- [ ] 4.2 Indicators from raw features
- [ ] 4.3 YARA tier
- [ ] 4.4 Local hash lists
- [ ] 4.5 capa on demand (optional)

## Phase 5 — Architecture & performance
- [ ] 5.1 FastAPI migration (v1 paths preserved)
- [ ] 5.2 SQLite storage
- [ ] 5.3 SSE scan events, single-read pipeline
- [ ] 5.4 App data in `%LOCALAPPDATA%`

## Phase 6 — UI/UX modernization
- [ ] 6.1 Vite + React + TS scaffold
- [ ] 6.2 Design system
- [ ] 6.3 Screen ports per preservation map (legacy UI kept at `/legacy`)
- [ ] 6.4 Research dashboards from `eval.json`

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
