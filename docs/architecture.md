# ThreatWeaver architecture (v0.2)

## Scan pipeline (v2 detector)

```
file ─► SHA-256 (single streaming read)
        │
        ├─► result cache  key = (SHA-256, engine fingerprint)          scanner/hash_cache.py
        │
        └─► isolated parsing worker (timeout, memory cap)              sandboxing/pool.py
              thrember raw features ─┬─► EMBER2024 v3 vector (2,568-D)  scanner/ember_v3.py
                                     └─► static indicators              detectors/indicators.py
                     │
                     ├─► LightGBM + Platt calibration → P(malicious)    models/bundle.py
                     ├─► TreeSHAP attribution (12 feature families)     explain/shap_groups.py
                     ├─► known-bad tier: hash lists, YARA                detectors/known_bad.py
                     ├─► opt-in hash reputation (MalwareBazaar)          detectors/threat_intel.py
                     └─► Authenticode / catalog signature (evidence)     scanner/signature_verifier.py
                                     │
                                     ▼
                        verdict policy v2 (pure, tested)                core/policy.py
     Known Malicious · Likely Malicious · Suspicious · Unfamiliar · Trusted Signer · Likely Benign · errors
```

The LightGBM bundle `artifacts/models/lgbm-v3-win64-dotnet` (Win64 + .NET) is the default detector; `--bundle` selects another signed bundle and `--legacy` the v0.1 neural model. If LightGBM or thrember is not installed, the legacy model is used and a notice is printed.

## Components

| Area | Module | Notes |
| :--- | :--- | :--- |
| Paths | `core/paths.py` | Per-user state in `%LOCALAPPDATA%\ThreatWeaver`; shipped resources from the install root |
| API | `app/api.py` (FastAPI), `app/server.py` | One endpoint implementation (`ApiCore`) shared by the FastAPI and stdlib servers; OpenAPI at `/api/openapi.json` |
| Request security | `app/security.py` | Token, Host/Origin checks, JSON-only, size cap, path policy |
| UI | `frontend/` → `app/static/v2` | React + TypeScript; classic UI at `/legacy` |
| Data | `data/ember_v3_dataset.py` | Dedupe, temporal validation split, memmaps, hashed manifest |
| Evaluation | `evaluation/harness.py`, `evaluation/gate.py` | `eval.json` (schema eval/1) is the only source of reported numbers; regression gate for new models |
| Model integrity | `models/signing.py` | Ed25519, fail-closed |
| Quarantine | `quarantine/manager.py` | Streaming XOR neutralisation, signed manifest |
| History | `reporting/report.py` | SQLite (WAL) |
| Watcher | `scanner/watcher.py` | Observational, file-system events |

## Training and evaluation flow

```
EMBER2024 JSONL (train, test, challenge)
   └─► tools/build_ember_v3_dataset.py   → data/ember_v3/ (+ manifest with SHA-256 of every file)
          └─► tools/train_lgbm.py         → artifacts/models/<id>/{model.txt, bundle.json, eval.json} (signed)
                 └─► tools/sign_release_checkpoints.py  (release signature for shipping)
   tools/train_mlp_v3.py  → neural comparison + novelty study
   tools/reproduce_v01_eval.py → continuity check of the v0.1 numbers
```

Thresholds are chosen on the temporal validation split (last 8 weeks of the training window) for 1% and 0.1% false-positive rates, then applied unchanged to the later test split.

## Data integrity notes

- EMBER2024 JSONL files contain every sample twice (copies differ only in `caps`); all counts and training use unique SHA-256 values.
- Signed text artifacts are stored byte-exact (`.gitattributes`), so signatures survive checkouts on any platform.
