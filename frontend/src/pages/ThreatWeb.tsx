import { useState } from "react";
import type { FsItem, ThreatNetwork } from "../lib/api";
import { pct, shortHash } from "../lib/format";
import { useApi } from "../lib/useApi";
import { Async, Empty } from "../components/States";
import { ThreatWebCanvas, WebFilter } from "../components/ThreatWebCanvas";
import { Verdict } from "../components/Verdict";

const FILTERS: { id: WebFilter; label: string }[] = [
  { id: "all", label: "All files" },
  { id: "threat", label: "Flagged" },
  { id: "novel", label: "Unfamiliar" },
  { id: "benign", label: "Clean" },
];

export function ThreatWeb() {
  const net = useApi<ThreatNetwork>("/api/threat-network");
  const [filter, setFilter] = useState<WebFilter>("all");
  const [sel, setSel] = useState<FsItem | null>(null);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Threat web</h1>
          <p>The latest scan laid out by folder. Colour is the file's real verdict; edges connect files to their folder.</p>
        </div>
        <div className="row">
          <div className="segmented" role="group" aria-label="Show">
            {FILTERS.map((f) => (
              <button key={f.id} aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
                {f.label}
              </button>
            ))}
          </div>
          <button onClick={net.reload}>Reload</button>
        </div>
      </div>
      <Async
        state={net}
        empty={(n) =>
          n.fs_items.length === 0 ? (
            <div className="panel">
              <Empty title="No scan to map yet">{n.reason ?? "Run a scan; its files will appear here grouped by folder."}</Empty>
            </div>
          ) : null
        }
      >
        {(n) => {
          const files = n.fs_items.filter((i) => i.kind === "file");
          const counts = {
            flagged: files.filter((f) => f.state === "threat").length,
            novel: files.filter((f) => f.state === "novel").length,
            clean: files.filter((f) => f.state === "benign").length,
          };
          return (
            <div className="grid-2" style={{ gridTemplateColumns: "1fr 300px" }}>
              <div className="section">
                <div className="panel" style={{ overflow: "hidden" }}>
                  <ThreatWebCanvas items={n.fs_items} edges={n.fs_edges} filter={filter} onSelect={setSel} />
                </div>
                <div className="legend">
                  <span><i className="box" style={{ background: "var(--danger)" }} />Flagged ({counts.flagged})</span>
                  <span><i className="box" style={{ background: "var(--novel)" }} />Unfamiliar ({counts.novel})</span>
                  <span><i className="box" style={{ background: "var(--ok)" }} />Clean ({counts.clean})</span>
                  <span><i className="box" style={{ background: "var(--ink)" }} />Folder</span>
                  <span>Scroll to zoom, drag to pan, double-click to reset.</span>
                </div>
              </div>
              <aside className="panel panel-pad section" aria-live="polite">
                {sel ? (
                  <>
                    <h2 style={{ wordBreak: "break-all" }}>{sel.name}</h2>
                    <p className="muted xs mono" style={{ wordBreak: "break-all" }}>{sel.path}</p>
                    {sel.kind === "file" ? (
                      <dl className="kv" style={{ gridTemplateColumns: "100px 1fr" }}>
                        <dt>Verdict</dt>
                        <dd>{sel.verdict ? <Verdict verdict={sel.verdict} /> : "—"}</dd>
                        <dt>Score</dt>
                        <dd>{pct(sel.prob)}</dd>
                        <dt>SHA-256</dt>
                        <dd className="mono">{shortHash(sel.sha256, 16)}</dd>
                      </dl>
                    ) : (
                      <p className="small muted">Folder group.</p>
                    )}
                    {sel.evidence && sel.evidence.length > 0 && (
                      <ul className="evidence">
                        {sel.evidence.slice(0, 5).map((e) => (
                          <li key={e}>{e}</li>
                        ))}
                      </ul>
                    )}
                  </>
                ) : (
                  <Empty title="Select a node">Click a file to see its verdict and evidence.</Empty>
                )}
              </aside>
            </div>
          );
        }}
      </Async>
    </>
  );
}
