import { useEffect, useState } from "react";
import { Copy, Lock, ThumbsDown, ThumbsUp, X } from "lucide-react";
import { api, ScanResultDto } from "../lib/api";
import { thresholdsFrom, useStatus } from "../lib/detector";
import { bytes, ms } from "../lib/format";
import { verdictInfo } from "../lib/verdicts";
import { useToast } from "./Toast";
import { Verdict } from "./Verdict";
import { VerdictScale } from "./VerdictScale";

function classify(evidence: string[]) {
  const out = { decision: [] as string[], attribution: [] as string[], indicators: [] as { sev: string; text: string }[], other: [] as string[] };
  for (const e of evidence) {
    const m = e.match(/^Static indicator \[(\w+)\]: (.*)$/);
    if (m) out.indicators.push({ sev: m[1], text: m[2] });
    else if (e.startsWith("Model attribution: ")) out.attribution.push(e.slice(19));
    else if (e.startsWith("Static indicator: ")) out.indicators.push({ sev: "low", text: e.slice(18) });
    else if (/score|threshold|Matches known|parsing|Not analysable|No model/i.test(e) && out.decision.length < 2) out.decision.push(e);
    else out.other.push(e);
  }
  const rank: Record<string, number> = { high: 0, medium: 1, low: 2 };
  out.indicators.sort((a, b) => (rank[a.sev] ?? 3) - (rank[b.sev] ?? 3));
  return out;
}

export function DetectionDrawer({ result, onClose }: { result: ScanResultDto; onClose: () => void }) {
  const status = useStatus();
  const thresholds = thresholdsFrom(status);
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const v = verdictInfo(result.verdict);
  const ev = classify(result.evidence_points || []);
  const expl = result.explanation;
  const maxAbs = Math.max(0.5, ...(expl?.groups ?? []).map((g) => Math.abs(g.contribution)));
  const hasScore = !["unsupported", "error"].includes(v.key);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function quarantine() {
    if (!window.confirm(`Move ${result.file_name} into the quarantine vault?\n\nIt is stored XOR-masked and can be restored later.`)) return;
    setBusy(true);
    try {
      await api.post("/api/quarantine", { file_path: result.file_path, reason: `Manual quarantine (${result.verdict})` });
      toast(`Quarantined ${result.file_name}.`);
      onClose();
    } catch (e) {
      toast((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }

  async function queue(label: 0 | 1) {
    setBusy(true);
    try {
      await api.post("/api/learning/queue", {
        file_path: result.file_path,
        label,
        detected_verdict: result.verdict,
        novelty_score: result.novelty_score,
      });
      toast(`Added ${result.file_name} to the learning queue as ${label ? "malicious" : "benign"}.`);
    } catch (e) {
      toast((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Details for ${result.file_name}`}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <Verdict verdict={result.verdict} />
          <button className="icon-btn" onClick={onClose} aria-label="Close details" title="Close (Esc)">
            <X />
          </button>
        </div>
        <div>
          <h1 style={{ wordBreak: "break-all", fontSize: "var(--fs-xl)" }}>{result.file_name}</h1>
          <p className="muted xs mono" style={{ wordBreak: "break-all", marginTop: 6 }}>
            {result.file_path}
          </p>
        </div>
        <div className="row">
          <button className="danger" disabled={busy} onClick={quarantine}>
            <Lock aria-hidden="true" />
            Quarantine file
          </button>
          <button disabled={busy} onClick={() => queue(1)}>
            <ThumbsDown aria-hidden="true" />
            Label malicious
          </button>
          <button disabled={busy} onClick={() => queue(0)}>
            <ThumbsUp aria-hidden="true" />
            Label benign
          </button>
          <button
            className="ghost"
            onClick={() => navigator.clipboard?.writeText(result.sha256).then(() => toast("SHA-256 copied."))}
          >
            <Copy aria-hidden="true" />
            Copy SHA-256
          </button>
        </div>

        {hasScore && (
          <section className="section">
            <div className="section-head">
              <h2>Where this file scores</h2>
              <span className="hint mono">{status?.detector?.id}</span>
            </div>
            <VerdictScale score={result.malware_probability} thresholds={thresholds} />
          </section>
        )}

        {ev.decision.length > 0 && (
          <section className="section">
            <h2>Why this verdict</h2>
            <ul className="evidence">
              {ev.decision.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
          </section>
        )}

        {expl && expl.groups.length > 0 && (
          <section className="section">
            <div className="section-head">
              <h2>What drove the score</h2>
              <span className="hint">Exact TreeSHAP contributions, in log-odds</span>
            </div>
            <div>
              {expl.groups.map((g) => {
                const w = (Math.abs(g.contribution) / maxAbs) * 50;
                const toMal = g.contribution > 0;
                return (
                  <div className="attr-row" key={g.group}>
                    <span>{g.label}</span>
                    <div className="attr-bar" aria-hidden="true">
                      <span
                        style={{
                          left: toMal ? "50%" : `${50 - w}%`,
                          width: `${w}%`,
                          background: toMal ? "var(--danger)" : "var(--ok)",
                        }}
                      />
                    </div>
                    <span className={`num small ${toMal ? "tone-danger" : "tone-ok"}`} style={{ textAlign: "right" }}>
                      {g.contribution > 0 ? "+" : ""}
                      {g.contribution.toFixed(2)}
                    </span>
                  </div>
                );
              })}
            </div>
            <p className="muted xs">Attributions explain the model's arithmetic, not the file's behaviour.</p>
          </section>
        )}

        {!expl && ev.attribution.length > 0 && (
          <section className="section">
            <h2>What drove the score</h2>
            <ul className="evidence">
              {ev.attribution.map((a) => (
                <li key={a}>{a}</li>
              ))}
            </ul>
          </section>
        )}

        {ev.indicators.length > 0 && (
          <section className="section">
            <h2>Static indicators</h2>
            <ul className="evidence">
              {ev.indicators.map((i) => (
                <li key={i.text} className={`sev-${i.sev}`}>
                  <span className="tag">{i.sev}</span> {i.text}
                </li>
              ))}
            </ul>
          </section>
        )}

        {ev.other.length > 0 && (
          <section className="section">
            <h2>Other evidence</h2>
            <ul className="evidence">
              {ev.other.map((o) => (
                <li key={o}>{o}</li>
              ))}
            </ul>
          </section>
        )}

        <section className="section">
          <h2>File</h2>
          <dl className="kv">
            <dt>SHA-256</dt>
            <dd className="mono">{result.sha256 || "—"}</dd>
            <dt>Size</dt>
            <dd>{bytes(result.file_size_bytes)}</dd>
            <dt>Analysed by</dt>
            <dd>{result.model_version}</dd>
            <dt>Analysis time</dt>
            <dd>{ms(result.scan_duration_ms)}</dd>
            {result.warning_message && (
              <>
                <dt>Warning</dt>
                <dd>{result.warning_message}</dd>
              </>
            )}
          </dl>
        </section>

      </aside>
    </>
  );
}
