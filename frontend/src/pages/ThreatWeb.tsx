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
          <p>A live map of the latest scan. Files gather around their folder; colour appears only where a verdict needs attention.</p>
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
            <div className="grid-2 web-layout">
              <div className="section">
                <div className="panel" style={{ overflow: "hidden" }}>
                  <ThreatWebCanvas items={n.fs_items} edges={n.fs_edges} filter={filter} onSelect={setSel} height={620} />
                </div>
                <div className="legend">
                  <span><i className="box" style={{ background: "var(--danger)" }} />Flagged ({counts.flagged})</span>
                  <span><i className="box" style={{ background: "var(--novel)" }} />Unfamiliar ({counts.novel})</span>
                  <span><i className="box" style={{ background: "var(--ink-3)" }} />Clean ({counts.clean})</span>
                  <span><i className="box" style={{ background: "transparent", boxShadow: "inset 0 0 0 1.5px var(--ink)", borderRadius: "50%" }} />Folder</span>
                  <span>Drag a node to move it, drag empty space to pan, scroll to zoom, double-click to fit.</span>
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
                  <>
                    <h2>Latest scan</h2>
                    <dl className="kv" style={{ gridTemplateColumns: "1fr auto" }}>
                      <dt>Folders</dt>
                      <dd className="mono">{n.fs_items.length - files.length}</dd>
                      <dt>Files</dt>
                      <dd className="mono">{files.length}</dd>
                      <dt>Flagged</dt>
                      <dd className="mono">{counts.flagged}</dd>
                      <dt>Unfamiliar</dt>
                      <dd className="mono">{counts.novel}</dd>
                      <dt>Clean</dt>
                      <dd className="mono">{counts.clean}</dd>
                    </dl>
                    <p className="small muted">Click a file or folder for its details. Drag nodes to pull clusters apart; double-click to fit everything.</p>
                  </>
                )}
              </aside>
            </div>
          );
        }}
      </Async>
    </>
  );
}
