# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primarily security researchers and analysts triaging Windows executables on their own machine or a lab box: they scan folders, review flagged files and the evidence behind each verdict, quarantine or restore files, label files for retraining, and check model performance and experiments. They read hashes, thresholds and false-positive rates fluently.

Secondarily, technical home users checking their own downloads and programs. Verdicts, reasons and actions must stay readable for them without the research detail.

## Product Purpose

ThreatWeaver is a research prototype for static, zero-execution Windows PE triage. It reads executables as data (never runs them), scores them with a calibrated LightGBM detector on EMBER2024 features, explains each score, and lets the user quarantine and restore files. Success is a user who can see quickly what needs attention, understand why, act on it, and trust that every number shown is real.

## Positioning

Transparent, measurable static triage: every verdict is drawn against the detector's real, validated thresholds, explained with per-file attributions and indicators, and every performance figure traces to a signed evaluation artifact. It does not claim to be an antivirus.

## Operating Context

Runs locally as a desktop app or a browser UI served from 127.0.0.1, behind a per-session API token. Typical workflow: start a scan of a folder or the whole system, watch results stream in, open flagged files to see score, reasons and indicators, quarantine or label them, and review scan history, families, model performance and experiments. An optional folder watcher observes and alerts only.

## Capabilities and Constraints

- On-demand static analysis only. No real-time protection, no blocking; the folder watcher only observes.
- Verdict vocabulary: Known Malicious, Likely Malicious, Suspicious, Unfamiliar, Trusted Signer, Likely Benign, Analysis Error, Unsupported Format, Cached.
- Detector thresholds: review threshold (1% FPR on validation) and high-confidence threshold (0.1% FPR on validation), exposed by `/api/status`.
- The interface must work fully offline: no external fonts, CDNs or network calls. Fonts are bundled.
- Frontend: Vite + React 18 + strict TypeScript, hand-written SVG charts, served by FastAPI under `/`.

## Brand Commitments

- Never imply real-time protection or antivirus replacement; label the product as on-demand static analysis and a research prototype.
- Show real numbers only: every metric, chart and count comes from real artifacts or scan history; no placeholder or decorative data.

## Evidence on Hand

- Signed evaluation artifacts: `artifacts/models/*/eval.json`, `artifacts/eval/*/eval.json`.
- Dataset summaries: `artifacts/dataset/family_summary.json`, `artifacts/dataset/*_manifest.json`.
- The user's own scan history (SQLite) and quarantine vault.
- No testimonials, customers or third-party benchmarks exist; none may be invented.

## Product Principles

1. Honesty over reassurance: show uncertainty, thresholds and limitations as they are.
2. Attention first: lead with what needs action, then the evidence, then the research detail.
3. Every verdict is explained: score, reason, attribution and indicators travel together.
4. Nothing executes: the interface never suggests running or opening a sample.

## Accessibility & Inclusion

Colour is never the only carrier of a verdict (icons and text accompany it); respect reduced-motion and reduced-transparency preferences.
