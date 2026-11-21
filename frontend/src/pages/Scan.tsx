import { useEffect, useRef, useState } from "react";
import { api, ScanEvents, ScanResultDto } from "../lib/api";
import { fileName } from "../lib/format";
import { useApi } from "../lib/useApi";
import { verdictInfo } from "../lib/verdicts";
import { DetectionDrawer } from "../components/DetectionDrawer";
import { ResultsTable } from "../components/ResultsTable";
import { Empty } from "../components/States";
import { useToast } from "../components/Toast";

const MAX_ROWS = 500;

interface Preset {
  group: string;
  label: string;
  path: string;
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
      if (!ev.is_scanning && ev.next >= ev.results_count && timer.current) {
        window.clearInterval(timer.current);
        timer.current = null;
      }
    } catch (e) {
      toast((e as Error).message, true);
    }
  }

  useEffect(() => {
    poll(); // show the last scan in this session, if any
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
      setResults([]);
      if (timer.current) window.clearInterval(timer.current);
      timer.current = window.setInterval(poll, 400);
    } catch (e) {
      toast((e as Error).message, true);
    }
  }

  async function cancel() {
    await api.post("/api/scan/cancel").catch(() => {});
    toast("Scan cancelled.");
  }

  const scanning = state?.is_scanning ?? false;
  const pctDone = state && state.total > 0 ? Math.min(100, (state.completed / state.total) * 100) : scanning ? 5 : 0;
  const flagged = results.filter((r) => verdictInfo(r.verdict).needsAttention).length;
  const shown = [...results].sort((a, b) => verdictInfo(a.verdict).rank - verdictInfo(b.verdict).rank).slice(0, MAX_ROWS);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scan</h1>
          <p>Files are read and parsed as data in isolated worker processes. Nothing is executed.</p>
        </div>
      </div>

      <section className="panel panel-pad section">
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault();
            start("custom");
          }}
        >
          <input
            type="text"
            style={{ flex: 1, minWidth: 280 }}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="C:\Users\you\Downloads  or a single .exe / .dll"
            aria-label="File or folder to scan"
          />
          <button type="submit" className="primary" disabled={scanning}>
            Scan
          </button>
          {scanning ? (
            <button type="button" onClick={cancel}>
              Cancel scan
            </button>
          ) : (
            <button type="button" onClick={() => start("full_system")}>
              Scan all drives
            </button>
          )}
        </form>
        <div className="row small">
          <label className="row">
            <input type="checkbox" checked={allFiles} onChange={(e) => setAllFiles(e.target.checked)} />
            Include files without a PE extension
          </label>
          {presets.data?.presets?.slice(0, 6).map((p) => (
            <button key={p.path} type="button" className="ghost" onClick={() => setTarget(p.path)} title={p.path}>
              {p.label}
            </button>
          ))}
        </div>
      </section>

      {state && (state.is_scanning || results.length > 0) && (
        <section className="section">
          <div className="section-head">
            <h2>
              {scanning ? "Scanning" : "Scan complete"}: {state.completed} of {state.total || "?"} files
            </h2>
            <span className="hint">
              {flagged} need attention{results.length > MAX_ROWS ? `; showing the ${MAX_ROWS} most urgent` : ""}
            </span>
          </div>
          <div className="progress" role="progressbar" aria-valuenow={Math.round(pctDone)} aria-valuemin={0} aria-valuemax={100}>
            <span style={{ width: `${pctDone}%` }} />
          </div>
          {scanning && state.current_file && <p className="muted small mono">{fileName(state.current_file)}</p>}
        </section>
      )}

      <section className="section">
        {results.length ? (
          <ResultsTable rows={shown} onOpen={setOpen} />
        ) : (
          !scanning && (
            <div className="panel">
              <Empty title="No results yet">Choose a folder above. Results appear here as each file is analysed.</Empty>
            </div>
          )
        )}
      </section>
      {open && <DetectionDrawer result={open} onClose={() => setOpen(null)} />}
    </>
  );
}
