import { useState } from "react";
import { ArrowRight, Cpu, Info, ScanSearch } from "lucide-react";
import type { DetectionRow, Insights, ScanResultDto, ThreatNetwork } from "../lib/api";
import { thresholdsFrom, useStatus } from "../lib/detector";
import { num } from "../lib/format";
import { go } from "../lib/router";
import { useApi } from "../lib/useApi";
import { verdictInfo } from "../lib/verdicts";
import { DetectionDrawer } from "../components/DetectionDrawer";
import { DailyTrend, ScoreField, VerdictTally } from "../components/Insights";
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
  const insights = useApi<Insights>("/api/insights");
  const detections = useApi<{ results: DetectionRow[] }>(`/api/detections?${q}&limit=200`);
  const web = useApi<ThreatNetwork>("/api/threat-network");
  const [open, setOpen] = useState<ScanResultDto | null>(null);
  const ds = status?.dataset;
  const det = status?.detector;
  const thresholds = thresholdsFrom(status);

  const counts = insights.data?.verdict_counts ?? {};
  const needing = Object.entries(counts).reduce((n, [v, c]) => n + (verdictInfo(v).needsAttention ? c : 0), 0);
  const unique = insights.data?.unique_files ?? 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Needs your attention</h1>
          <p className="lede">
            {insights.data ? (
              unique ? (
                <>
                  <strong>{num(needing)}</strong> of {num(unique)} files with saved results need a look.
                </>
              ) : (
                "Nothing scanned yet. Pick a folder to see where its files score."
              )
            ) : (
              "Loading your scan history…"
            )}
          </p>
        </div>
        <button className="primary lg" onClick={() => go("scan")}>
          <ScanSearch aria-hidden="true" />
          Start a scan
        </button>
      </div>

      <section className="panel panel-pad" aria-labelledby="tally-h">
        <div className="panel-title">
          <h2 id="tally-h">Every file, by latest verdict</h2>
          <span className="hint">Select a verdict to see its files</span>
        </div>
        <Async state={insights}>{(d) => (d.unique_files ? <VerdictTally data={d} /> : <Empty title="No files yet">Scanned files are counted here by their most recent verdict.</Empty>)}</Async>
      </section>

      <div className="grid-split">
        <section className="panel panel-pad" aria-labelledby="field-h">
          <div className="panel-title">
            <h2 id="field-h">Scores from the current detector</h2>
            <span className="hint mono">{det?.id ?? ""}</span>
          </div>
          <Async state={insights}>{(d) => <ScoreField data={d.score_histogram} thresholds={thresholds} modelId={det?.id} totalFiles={d.unique_files} />}</Async>
        </section>
        <section className="panel panel-pad" aria-labelledby="trend-h">
          <div className="panel-title">
            <h2 id="trend-h">Scan activity</h2>
            <span className="hint">by scan day</span>
          </div>
          <Async state={insights}>
            {(d) => (d.daily.length ? <DailyTrend daily={d.daily} /> : <Empty title="No scans yet">Each scan day appears here.</Empty>)}
          </Async>
        </section>
      </div>

      <section className="section" aria-labelledby="flagged-h">
        <div className="section-head">
          <h2 id="flagged-h">Flagged files</h2>
          <button className="ghost" onClick={() => go("detections")}>
            All detections
            <ArrowRight aria-hidden="true" />
          </button>
        </div>
        <Async
          state={detections}
          empty={(d) =>
            d.results.length === 0 ? (
              <div className="panel">
                <Empty title="Nothing flagged" action={<button onClick={() => go("scan")}>Scan a folder</button>}>
                  Anything the detector flags appears here with the evidence behind it.
                </Empty>
              </div>
            ) : null
          }
        >
          {(d) => <ResultsTable rows={latestPerFile(d.results).slice(0, 8)} onOpen={setOpen} showTime={false} />}
        </Async>
      </section>

      <section className="panel panel-pad section" aria-label="This installation">
        <p className="install-line">
          <Cpu aria-hidden="true" />
          <span>
            Detector <b>{det ? (det.kind === "lightgbm" ? "LightGBM" : det.kind === "legacy" ? "Neural (legacy)" : "none loaded") : "—"}</b>{" "}
            <span className="mono xs">{det?.id ?? ""}</span>
          </span>
          <span>
            <a href="#/quarantine">{num(status?.quarantine_count)} in quarantine</a>
          </span>
          <span>
            EMBER2024 data on disk: {ds?.available ? <b>{num(ds.unique_samples ?? ds.samples)}</b> : "—"} unique samples
          </span>
        </p>
        <p className="install-line">
          <Info aria-hidden="true" />
          {status?.protection_note ?? "Loading status…"}
        </p>
      </section>

      <section className="section" aria-labelledby="web-h">
        <div className="section-head">
          <h2 id="web-h">Latest scan, by folder</h2>
          <button className="ghost" onClick={() => go("web")}>
            Open threat web
            <ArrowRight aria-hidden="true" />
          </button>
        </div>
        <div className="panel" style={{ padding: 8 }}>
          <Async state={web}>{(w) => <ThreatWebCanvas items={w.fs_items} edges={w.fs_edges} height={320} />}</Async>
        </div>
      </section>

      {open && <DetectionDrawer result={open} onClose={() => setOpen(null)} />}
    </>
  );
}
