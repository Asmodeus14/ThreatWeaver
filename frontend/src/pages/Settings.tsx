import { useEffect, useState } from "react";
import { api, ScanResultDto } from "../lib/api";
import { Verdict } from "../components/Verdict";
import { useStatus } from "../lib/detector";
import { useToast } from "../components/Toast";

interface SettingsResponse {
  settings: {
    novelty_threshold: number;
    max_workers: number;
    enable_signature_verifier: boolean;
    enable_hash_cache: boolean;
    cached_entries: number;
  };
}

export function Settings() {
  const status = useStatus();
  const toast = useToast();
  const [s, setS] = useState<SettingsResponse["settings"] | null>(null);

  useEffect(() => {
    // An empty settings POST returns current values without changing anything.
    api.post<SettingsResponse>("/api/settings", {}).then((r) => setS(r.settings)).catch((e) => toast(e.message, true));
  }, [toast]);

  async function save(change: Record<string, unknown>, done: string) {
    try {
      const r = await api.post<SettingsResponse>("/api/settings", change);
      setS(r.settings);
      toast(done);
    } catch (e) {
      toast((e as Error).message, true);
    }
  }

  if (!s) return <p className="muted">Loading settings…</p>;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>Changes apply to this session immediately. Any change that can alter a verdict also invalidates cached results.</p>
        </div>
      </div>

      <section className="panel panel-pad section">
        <h2>Detection</h2>
        <label className="row">
          <input type="checkbox" checked={s.enable_signature_verifier} onChange={(e) => save({ enable_signature_verifier: e.target.checked }, "Signature checks updated.")} />
          Check Authenticode signatures
        </label>
        <p className="muted small">
          {status?.detector?.kind === "lightgbm"
            ? "With the LightGBM detector a valid signature is evidence only: it can mark a low-scoring file as a trusted signer but never hides a high score."
            : "With the legacy model a valid signature currently skips the model entirely (planned to change once the new model is the default)."}
        </p>
        <label className="row">
          Novelty threshold (legacy model)
          <input
            type="number"
            step="0.01"
            min="0"
            max="2"
            defaultValue={s.novelty_threshold}
            onBlur={(e) => save({ novelty_threshold: Number(e.target.value) }, "Novelty threshold updated.")}
            style={{ width: 100 }}
          />
        </label>
      </section>

      <WatchPanel />

      <section className="panel panel-pad section">
        <h2>Performance</h2>
        <label className="row">
          Parallel scan workers
          <input
            type="number"
            min="1"
            max="16"
            defaultValue={s.max_workers}
            onBlur={(e) => save({ max_workers: Math.max(1, Math.min(16, Number(e.target.value))) }, "Workers updated.")}
            style={{ width: 80 }}
          />
        </label>
        <label className="row">
          <input type="checkbox" checked={s.enable_hash_cache} onChange={(e) => save({ enable_hash_cache: e.target.checked }, "Result cache updated.")} />
          Reuse results for files whose content has not changed ({s.cached_entries.toLocaleString()} cached)
        </label>
        <div>
          <button onClick={() => window.confirm("Clear all cached results?") && save({ clear_cache: true }, "Cache cleared.")}>Clear cache</button>
        </div>
      </section>

      <section className="panel panel-pad section">
        <h2>About</h2>
        <dl className="kv">
          <dt>Version</dt>
          <dd>{status?.version}</dd>
          <dt>Model</dt>
          <dd>{status?.model_version}</dd>
          <dt>Device</dt>
          <dd>{status?.device}</dd>
          <dt>Protection</dt>
          <dd>{status?.protection_note}</dd>
        </dl>
      </section>
    </>
  );
}

interface WatchStatus {
  running: boolean;
  mode: string;
  folder?: string;
  events?: number;
  scanned?: number;
  recent?: ScanResultDto[];
}

/** Observational folder watcher: scans new or changed executables; never blocks or deletes. */
function WatchPanel() {
  const toast = useToast();
  const [st, setSt] = useState<WatchStatus | null>(null);
  const [folder, setFolder] = useState("");
  useEffect(() => {
    let alive = true;
    const load = () => api.get<WatchStatus>("/api/watch").then((r) => alive && setSt(r)).catch(() => {});
    load();
    const t = window.setInterval(load, 3000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);
  async function act(action: "start" | "stop") {
    try {
      setSt(await api.post<WatchStatus>("/api/watch", action === "start" ? { action, path: folder } : { action }));
      toast(action === "start" ? "Watching folder." : "Stopped watching.");
    } catch (e) {
      toast((e as Error).message, true);
    }
  }
  return (
    <section className="panel panel-pad section">
      <h2>Watch a folder</h2>
      <p className="muted small">
        Scans executables as they appear or change, for example in Downloads. Observation only: files are never blocked, moved or deleted
        automatically. This is not real-time protection.
      </p>
      {st?.running ? (
        <>
          <div className="row small">
            <span>
              Watching <span className="mono">{st.folder}</span> ({st.mode === "events" ? "file-system events" : "polling"}); {st.scanned} scanned
            </span>
            <button onClick={() => act("stop")}>Stop watching</button>
          </div>
          {st.recent && st.recent.length > 0 && (
            <ul className="evidence">
              {st.recent.slice(0, 8).map((r, i) => (
                <li key={r.sha256 + i} className="row" style={{ justifyContent: "space-between" }}>
                  <span>{r.file_name}</span>
                  <Verdict verdict={r.verdict} />
                </li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault();
            act("start");
          }}
        >
          <input type="text" value={folder} onChange={(e) => setFolder(e.target.value)} placeholder="C:\Users\you\Downloads" aria-label="Folder to watch" style={{ flex: 1, minWidth: 260 }} />
          <button type="submit" disabled={!folder.trim()}>
            Start watching
          </button>
        </form>
      )}
    </section>
  );
}
