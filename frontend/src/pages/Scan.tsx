import { useEffect, useMemo, useRef, useState } from "react";
import { FileCode2, Folder, FolderSearch, HardDrive, Play, Square } from "lucide-react";
import { api, ScanEvents, ScanResultDto } from "../lib/api";
import { num } from "../lib/format";
import { useApi } from "../lib/useApi";
import { verdictInfo } from "../lib/verdicts";
import { DetectionDrawer } from "../components/DetectionDrawer";
import { ResultsTable } from "../components/ResultsTable";
import { Empty } from "../components/States";
import { VerdictGlyph } from "../components/Verdict";
import { useToast } from "../components/Toast";

const MAX_ROWS = 500;

interface Preset {
  group: string;
  label: string;
  path: string;
}

const duration = (s: number | null) => {
  if (s === null || !isFinite(s)) return "—";
  if (s < 60) return `${Math.max(1, Math.round(s))}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${Math.round(s % 60)}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
};

function presetIcon(p: Preset) {
  if (/\.(exe|dll|sys|scr|ocx|cpl)$/i.test(p.path)) return FileCode2;
  if (/^[A-Za-z]:\\?$/.test(p.path)) return HardDrive;
  return Folder;
}

/** "C:\Windows\System32\cmd.exe (Command Shell)" -> "Command Shell"; "Name (path)" -> "Name". */
function presetTitle(p: Preset): string {
  const m = p.label.match(/^(.*?)\s*\(([^)]*)\)\s*$/);
  if (!m) return p.label;
  const [, head, inner] = m;
  if (head.toLowerCase() === p.path.toLowerCase()) return inner;
  return head;
}

function Ring({ value, state }: { value: number; state: "running" | "indeterminate" | "done" | "stopped" }) {
  const R = 62;
  const C = 2 * Math.PI * R;
  const shown = state === "indeterminate" ? 0.22 : value / 100;
  return (
    <div className="ring" data-state={state}>
      <svg viewBox="0 0 148 148" aria-hidden="true">
        <circle className="ring-bg" cx="74" cy="74" r={R} fill="none" strokeWidth="10" />
        <circle className="ring-fg" cx="74" cy="74" r={R} fill="none" strokeWidth="10" strokeDasharray={C} strokeDashoffset={C * (1 - shown)} />
      </svg>
      <div className="ring-center">
        <b>{state === "indeterminate" ? "…" : `${Math.floor(value)}%`}</b>
        <small>{state === "done" ? "complete" : state === "stopped" ? "stopped" : state === "indeterminate" ? "counting files" : "analysed"}</small>
      </div>
    </div>
  );
}

export function ScanPage() {
  const toast = useToast();
  const presets = useApi<{ presets: Preset[] }>("/api/browse-paths");
  const [target, setTarget] = useState("");
  const [allFiles, setAllFiles] = useState(false);
  const [state, setState] = useState<Omit<ScanEvents, "new_results"> | null>(null);
  const [results, setResults] = useState<ScanResultDto[]>([]);
  const [open, setOpen] = useState<ScanResultDto | null>(null);
  const cursor = useRef({ next: 0, seq: null as number | null });
  const timer = useRef<number | null>(null);
  // Rate and ETA are measured in this browser from progress over time.
  const clock = useRef<{ t0: number; c0: number } | null>(null);
  const [rate, setRate] = useState<number | null>(null);
  const [elapsed, setElapsed] = useState<number | null>(null);

  async function poll() {
    try {
      const c = cursor.current;
      const ev = await api.get<ScanEvents>(`/api/scan/events?since=${c.next}&seq=${c.seq ?? ""}`);
      const fresh = ev.scan_seq !== c.seq;
      c.seq = ev.scan_seq;
      c.next = ev.next;
      const { new_results, ...rest } = ev;
      setState(rest);
      if (fresh || new_results.length) setResults((prev) => (fresh ? new_results : prev.concat(new_results)).slice(-20000));
      const now = performance.now();
      if (ev.is_scanning) {
        if (!clock.current || fresh) clock.current = { t0: now, c0: ev.completed };
        const dt = (now - clock.current.t0) / 1000;
        setElapsed(dt);
        if (dt > 1.5) setRate((ev.completed - clock.current.c0) / dt);
        if (!timer.current) timer.current = window.setInterval(poll, 500);
      }
      if (!ev.is_scanning && ev.next >= ev.results_count && timer.current) {
        window.clearInterval(timer.current);
        timer.current = null;
      }
    } catch (e) {
      toast((e as Error).message, true);
    }
  }

  useEffect(() => {
    poll(); // picks up a scan already running, or the last one in this session
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function start(mode: "custom" | "full_system") {
    if (mode === "custom" && !target.trim()) return toast("Enter a file or folder path to scan.", true);
    if (mode === "full_system" && !window.confirm("Scan every fixed drive? This can take a long time.")) return;
    try {
      await api.post("/api/scan", { target_path: target.trim(), scan_mode: mode, all_files: allFiles });
      cursor.current = { next: 0, seq: null };
      clock.current = null;
      setRate(null);
      setElapsed(null);
      setResults([]);
      if (timer.current) window.clearInterval(timer.current);
      timer.current = window.setInterval(poll, 500);
      toast(mode === "full_system" ? "Scanning all fixed drives." : "Scan started.");
    } catch (e) {
      toast((e as Error).message, true);
    }
  }

  async function cancel() {
    await api.post("/api/scan/cancel").catch(() => {});
    toast("Scan cancelled.");
  }

  const scanning = state?.is_scanning ?? false;
  const total = state?.total ?? 0;
  const done = state?.completed ?? 0;
  const pctDone = total > 0 ? Math.min(100, (done / total) * 100) : 0;
  const finished = !scanning && total > 0 && done >= total;
  const ringState = scanning ? (total > 0 ? "running" : "indeterminate") : finished ? "done" : "stopped";
  const eta = scanning && rate && rate > 0 && total > done ? (total - done) / rate : null;

  const tallies = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of results) m.set(r.verdict, (m.get(r.verdict) ?? 0) + 1);
    return [...m.entries()].map(([v, n]) => ({ v, n, info: verdictInfo(v) })).sort((a, b) => a.info.rank - b.info.rank);
  }, [results]);
  const flagged = tallies.reduce((n, t) => n + (t.info.needsAttention ? t.n : 0), 0);
  const shown = useMemo(
    () => [...results].sort((a, b) => verdictInfo(a.verdict).rank - verdictInfo(b.verdict).rank).slice(0, MAX_ROWS),
    [results],
  );
  const showLive = !!state && (scanning || results.length > 0);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scan</h1>
          <p>Files are read and parsed as data in isolated worker processes. Nothing is executed.</p>
        </div>
      </div>

      <section className="panel panel-pad scan-target" aria-label="Choose what to scan">
        <form
          className="row"
          style={{ flexWrap: "nowrap", gap: 12 }}
          onSubmit={(e) => {
            e.preventDefault();
            start("custom");
          }}
        >
          <label className="target-input" style={{ flex: 1 }}>
            <FolderSearch aria-hidden="true" />
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="C:\Users\you\Downloads  or a single .exe / .dll"
              aria-label="File or folder to scan"
              spellCheck={false}
            />
          </label>
          {scanning ? (
            <button type="button" className="danger lg" onClick={cancel}>
              <Square aria-hidden="true" />
              Cancel scan
            </button>
          ) : (
            <button type="submit" className="primary lg">
              <Play aria-hidden="true" />
              Scan
            </button>
          )}
        </form>

        {!!presets.data?.presets?.length && (
          <div className="quick-targets" role="group" aria-label="Quick targets">
            {presets.data.presets.slice(0, 8).map((p) => {
              const Icon = presetIcon(p);
              return (
                <button key={p.path} type="button" className="quick-target" aria-pressed={target === p.path} onClick={() => setTarget(p.path)} title={p.path}>
                  <Icon aria-hidden="true" />
                  <span>
                    <b>{presetTitle(p)}</b>
                    <small>{p.path}</small>
                  </span>
                </button>
              );
            })}
          </div>
        )}

        <div className="row" style={{ justifyContent: "space-between" }}>
          <label className="row small">
            <input type="checkbox" checked={allFiles} onChange={(e) => setAllFiles(e.target.checked)} />
            Include files without a PE extension
          </label>
          <button type="button" className="ghost" onClick={() => start("full_system")} disabled={scanning}>
            <HardDrive aria-hidden="true" />
            Scan all fixed drives
          </button>
        </div>
      </section>

      {showLive && (
        <section className="panel panel-pad" aria-labelledby="live-h" aria-busy={scanning}>
          <div className="panel-title">
            <h2 id="live-h">{scanning ? "Scanning" : finished ? "Last scan" : total > 0 ? `Last scan stopped at ${num(done)} of ${num(total)}` : "Last scan"}</h2>
            <span className="hint">
              {num(flagged)} need attention{results.length > MAX_ROWS ? ` · table shows the ${MAX_ROWS} most urgent` : ""}
            </span>
          </div>
          <div className="live">
            <div role="progressbar" aria-label="Scan progress" aria-valuenow={Math.round(pctDone)} aria-valuemin={0} aria-valuemax={100}>
              <Ring value={pctDone} state={ringState} />
            </div>
            <div className="section" style={{ minWidth: 0 }}>
              <dl className="live-stats">
                <div>
                  <dt>Files</dt>
                  <dd>
                    {num(done)}
                    <span className="muted xs"> / {total ? num(total) : "?"}</span>
                  </dd>
                </div>
                <div>
                  <dt>Rate</dt>
                  <dd>{scanning && rate !== null ? `${rate.toFixed(rate < 10 ? 1 : 0)}/s` : "—"}</dd>
                </div>
                <div>
                  <dt>Remaining</dt>
                  <dd>{scanning ? duration(eta) : "—"}</dd>
                </div>
                <div>
                  <dt>Elapsed</dt>
                  <dd>{duration(elapsed)}</dd>
                </div>
              </dl>
              {scanning && state?.current_file && (
                <div className="live-file" title={state.current_file}>
                  {state.current_file}
                </div>
              )}
              <div className="chips" aria-label="Verdicts so far">
                {tallies.map((t) => (
                  <span key={t.v} className={`chip pop tone-${t.info.tone}`}>
                    <VerdictGlyph kind={t.info.key} />
                    <span style={{ color: "var(--ink-2)" }}>{t.info.label}</span>
                    <b key={t.n}>{num(t.n)}</b>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </section>
      )}

      <section className="section">
        {results.length ? (
          <ResultsTable rows={shown} onOpen={setOpen} />
        ) : (
          !scanning && (
            <div className="panel">
              <Empty title="No results yet">Choose a folder or one of the quick targets above. Each file appears here the moment it is analysed.</Empty>
            </div>
          )
        )}
      </section>
      {open && <DetectionDrawer result={open} onClose={() => setOpen(null)} />}
    </>
  );
}
