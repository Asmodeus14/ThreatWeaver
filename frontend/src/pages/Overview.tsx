import { useState } from "react";
import type { DetectionRow, ScanResultDto, ThreatNetwork } from "../lib/api";
import { useStatus } from "../lib/detector";
import { num } from "../lib/format";
import { go } from "../lib/router";
import { useApi } from "../lib/useApi";
import { DetectionDrawer } from "../components/DetectionDrawer";
import { ResultsTable } from "../components/ResultsTable";
import { Async, Empty } from "../components/States";
import { ThreatWebCanvas } from "../components/ThreatWebCanvas";

const ATTENTION = ["Known Malicious", "Likely Malicious", "Suspicious", "Unfamiliar / Out-of-Distribution", "Analysis Error"];
const q = ATTENTION.map((v) => `verdict=${encodeURIComponent(v)}`).join("&");

/** Results arrive newest first; keep each file's most recent verdict only. */
function latestPerFile(rows: DetectionRow[]): ScanResultDto[] {
  const seen = new Set<string>();
  return (rows as unknown as ScanResultDto[]).filter((r) => {
    const key = r.sha256 || r.file_path;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function Overview() {
  const status = useStatus();
  const detections = useApi<{ results: DetectionRow[] }>(`/api/detections?${q}&limit=200`);
  const web = useApi<ThreatNetwork>("/api/threat-network");
  const [open, setOpen] = useState<ScanResultDto | null>(null);
  const ds = status?.dataset;
  const det = status?.detector;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Needs your attention</h1>
          <p>Files from your scans that the detector flagged, could not analyse, or does not recognise.</p>
        </div>
        <button className="primary" onClick={() => go("scan")}>
          Start a scan
        </button>
      </div>

      <section className="section">
        <Async
          state={detections}
          empty={(d) =>
            d.results.length === 0 ? (
              <div className="panel">
                <Empty title="Nothing flagged yet" action={<button onClick={() => go("scan")}>Scan a folder</button>}>
                  Scan a folder or file; anything flagged appears here with the evidence behind it.
                </Empty>
              </div>
            ) : null
          }
        >
          {(d) => (
            <>
              <ResultsTable rows={latestPerFile(d.results).slice(0, 8)} onOpen={setOpen} showTime={false} />
              <div>
                <button className="ghost" onClick={() => go("detections")}>
                  See all detections
                </button>
              </div>
            </>
          )}
        </Async>
      </section>

      <section className="section">
        <h2>This installation</h2>
        <dl className="facts">
          <div className="fact">
            <dt>Detector</dt>
            <dd>{det ? (det.kind === "lightgbm" ? "LightGBM" : det.kind === "legacy" ? "Neural (legacy)" : "None loaded") : "—"}</dd>
            <div className="sub">{det?.id ?? ""}</div>
          </div>
          <div className="fact">
            <dt>Files scanned</dt>
            <dd>{num(status?.total_files_scanned)}</dd>
            <div className="sub">across saved scan history</div>
          </div>
          <div className="fact">
            <dt>In quarantine</dt>
            <dd>{num(status?.quarantine_count)}</dd>
            <div className="sub">
              <a href="#/quarantine">Open vault</a>
            </div>
          </div>
          <div className="fact">
            <dt>Training data on disk</dt>
            <dd>{ds?.available ? num(ds.unique_samples ?? ds.samples) : "—"}</dd>
            <div className="sub">
              {ds?.available
                ? ds.unique_samples
                  ? `unique EMBER2024 samples (${num(ds.samples)} records)`
                  : "EMBER2024 records"
                : ds?.reason ?? ""}
            </div>
          </div>
        </dl>
        <p className="note">{status?.protection_note ?? "Loading status…"}</p>
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Latest scan, by folder</h2>
          <a className="hint" href="#/web">
            Open threat web
          </a>
        </div>
        <Async state={web}>{(w) => <ThreatWebCanvas items={w.fs_items} edges={w.fs_edges} height={320} />}</Async>
      </section>

      {open && <DetectionDrawer result={open} onClose={() => setOpen(null)} />}
    </>
  );
}
