import type { Insights } from "../lib/api";
import type { Thresholds } from "../lib/detector";
import { num, pct } from "../lib/format";
import { go } from "../lib/router";
import { verdictInfo } from "../lib/verdicts";
import { VerdictGlyph } from "./Verdict";

const FILTER_FOR: Record<string, string> = {
  "Known Malicious": "malicious",
  "Likely Malicious": "malicious",
  Suspicious: "suspicious",
  "Unfamiliar / Out-of-Distribution": "unfamiliar",
  "Likely Benign": "clean",
  "Trusted Signer": "clean",
};

/** Every verdict in the user's history, each file counted once at its latest verdict. */
export function VerdictTally({ data }: { data: Insights }) {
  const total = data.unique_files;
  const entries = Object.entries(data.verdict_counts)
    .map(([verdict, count]) => ({ verdict, count, info: verdictInfo(verdict) }))
    .sort((a, b) => a.info.rank - b.info.rank);
  return (
    <div className="tally">
      <div className="tally-bar" role="img" aria-label={entries.map((e) => `${e.info.label} ${e.count}`).join(", ")}>
        {entries.map((e) => (
          <span key={e.verdict} className={`bg-${e.info.tone}`} style={{ flexGrow: e.count }} title={`${e.info.label}: ${num(e.count)}`} />
        ))}
      </div>
      <div className="tally-items">
        {entries.map((e) => (
          <button
            key={e.verdict}
            className="tally-item"
            data-zero={e.count === 0}
            onClick={() => go("detections", { filter: FILTER_FOR[e.verdict] ?? "all" })}
            aria-label={`${e.info.label}: ${e.count} files. Show them`}
          >
            <span className={`verdict tone-${e.info.tone}`}>
              <VerdictGlyph kind={e.info.key} />
              {e.info.label}
            </span>
            <span className="count-big">{num(e.count)}</span>
            <span className="share">{total ? pct(e.count / total) : "—"} of files</span>
          </button>
        ))}
      </div>
    </div>
  );
}

const TONE_FILL: Record<string, string> = {
  danger: "var(--danger)",
  warning: "var(--warning)",
  novel: "var(--novel)",
  trusted: "var(--trusted)",
  ok: "var(--ok)",
  muted: "var(--muted)",
};

/**
 * The score field: files the active detector has scored, one dot per file at its score,
 * coloured by the file's verdict, over the detector's real zones. Columns taller than the
 * cap keep the most urgent verdicts as dots and print the column's true count above.
 */
export function ScoreField({
  data,
  thresholds,
  modelId,
  totalFiles,
}: {
  data: Insights["score_histogram"];
  thresholds: Thresholds | null;
  modelId?: string;
  totalFiles?: number;
}) {
  const W = 1000;
  const H = 350;
  const top = 70;
  const bottom = 40;
  const plotH = H - top - bottom;
  const bins = data.bins || data.counts.length || 40;
  const colW = W / bins;
  const CAP = 11;
  const step = Math.min(colW - 2, (plotH - 26) / CAP);
  const r = Math.max(3, Math.min(colW / 2 - 1.5, step / 2 - 1));
  const lo = thresholds?.low ?? 0.5;
  const hi = thresholds?.high ?? lo;
  const two = !!thresholds && hi !== lo;
  const x = (v: number) => v * W;
  const base = top + plotH;
  const byVerdict = Object.entries(data.by_verdict ?? {})
    .map(([v, counts]) => ({ info: verdictInfo(v), counts }))
    .sort((p, q) => p.info.rank - q.info.rank); // urgent first: they always get a dot
  const present = byVerdict.filter((v) => v.counts.some(Boolean));

  return (
    <div className="score-field">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Scores of ${data.n} files analysed by ${modelId ?? "the active detector"}`}>
        <rect className="zone-fill" x={0} y={top} width={x(lo)} height={plotH} fill="var(--zone-low)" />
        <rect className="zone-fill" x={x(lo)} y={top} width={x((two ? hi : 1) - lo)} height={plotH} fill="var(--zone-review)" />
        {two && <rect className="zone-fill" x={x(hi)} y={top} width={x(1 - hi)} height={plotH} fill="var(--zone-high)" />}
        <line x1={0} x2={W} y1={base} y2={base} stroke="var(--rule-strong)" />
        {thresholds && (
          <>
            <line x1={x(lo)} x2={x(lo)} y1={top - 8} y2={base} stroke="var(--ink-3)" strokeDasharray="3 4" />
            <text x={x(lo) - 10} y={top - 16} textAnchor="end" className="zone-label" fill="var(--ink-2)">
              Review from {pct(lo)}
            </text>
          </>
        )}
        {two && (
          <>
            <line x1={x(hi)} x2={x(hi)} y1={top - 36} y2={base} stroke="var(--ink-3)" strokeDasharray="3 4" />
            <text x={W} y={top - 44} textAnchor="end" className="zone-label" fill="var(--ink)">
              High from {pct(hi)}
            </text>
          </>
        )}
        {data.counts.map((c, i) => {
          if (!c) return null;
          const cx = (i + 0.5) * colW;
          const dots: string[] = [];
          for (const v of byVerdict) for (let k = 0; k < v.counts[i] && dots.length < CAP; k++) dots.push(TONE_FILL[v.info.tone]);
          while (dots.length < Math.min(c, CAP)) dots.push(TONE_FILL.muted); // older rows without per-verdict data
          dots.reverse(); // urgent verdicts end up on top of the stack
          return (
            <g key={i}>
              <title>{`${num(c)} file${c === 1 ? "" : "s"} scored ${pct(i / bins, 1)}–${pct((i + 1) / bins, 1)}`}</title>
              <rect x={i * colW} y={top} width={colW} height={plotH} fill="transparent" />
              {dots.map((fill, k) => (
                <circle key={k} className="dot" cx={cx} cy={base - r - 3 - k * step} r={r} fill={fill} />
              ))}
              {c > CAP && (
                <text x={cx} y={base - r - 3 - CAP * step - 4} textAnchor="middle" className="col-count">
                  {num(c)}
                </text>
              )}
            </g>
          );
        })}
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <text key={t} x={x(t)} y={H - 8} textAnchor={t === 0 ? "start" : t === 1 ? "end" : "middle"}>
            {Math.round(t * 100)}%
          </text>
        ))}
        {data.n === 0 && (
          <text x={W / 2} y={top + plotH / 2} textAnchor="middle" style={{ fontFamily: "var(--font)", fontSize: 20, fill: "var(--ink-2)" }}>
            No files scored by this detector yet. Scan a folder to fill the field.
          </text>
        )}
      </svg>
      <div className="score-field-key">
        {present.map((v) => (
          <span key={v.info.key + v.info.label}>
            <i style={{ background: TONE_FILL[v.info.tone] }} />
            {v.info.label}
          </span>
        ))}
        {thresholds && (
          <span className="key-zones">
            Shaded zones: review from {pct(lo)}
            {two ? `, high confidence from ${pct(hi)}` : ""}
          </span>
        )}
        <span>
          One dot per file{data.counts.some((c) => c > CAP) ? "; tall columns show their count" : ""}
          {typeof totalFiles === "number" ? ` · ${num(data.n)} of ${num(totalFiles)} files were scored by this detector` : ""}
        </span>
      </div>
    </div>
  );
}

const shortDay = (d: string) => {
  const dt = new Date(`${d}T00:00:00`);
  return isNaN(dt.getTime()) ? d : dt.toLocaleDateString(undefined, { month: "short", day: "numeric" });
};

/** Files scanned and flagged on each day that had scans (days without scans are not drawn). */
export function DailyTrend({ daily }: { daily: Insights["daily"] }) {
  const W = 600;
  const H = 330;
  const top = 24;
  const bottom = 36;
  const left = 4;
  const plotH = H - top - bottom;
  const n = daily.length;
  const maxV = Math.max(1, ...daily.map((d) => d.scanned));
  const gutter = 44; // y-axis labels live here, clear of the bars
  const slot = (W - left - gutter) / Math.max(1, n);
  const bw = Math.max(6, Math.min(36, slot * 0.62));
  const y = (v: number) => top + plotH - (v / maxV) * plotH;
  const labelIdx = n <= 1 ? [0] : n <= 4 ? daily.map((_, i) => i) : [0, Math.floor((n - 1) / 2), n - 1];

  return (
    <div className="trend">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Files scanned and flagged on the last ${n} scan days`}>
        {[0.5, 1].map((t) => (
          <g key={t}>
            <line x1={left} x2={W - gutter + 6} y1={y(maxV * t)} y2={y(maxV * t)} stroke="var(--rule)" />
            <text x={W} y={y(maxV * t) - 4} textAnchor="end">
              {num(Math.round(maxV * t))}
            </text>
          </g>
        ))}
        <line x1={left} x2={W - gutter + 6} y1={y(0)} y2={y(0)} stroke="var(--rule-strong)" />
        {daily.map((d, i) => {
          const cx = left + slot * (i + 0.5);
          return (
            <g key={d.day} className="day">
              <title>{`${shortDay(d.day)}: ${num(d.scanned)} files scanned, ${num(d.flagged)} needed attention`}</title>
              <rect x={cx - slot / 2} y={top} width={slot} height={plotH} fill="transparent" />
              <rect className="bar-total" x={cx - bw / 2} y={y(d.scanned)} width={bw} height={Math.max(1, y(0) - y(d.scanned))} rx={4} />
              {d.flagged > 0 && (
                <rect className="bar-flag" x={cx - bw / 2} y={y(d.flagged)} width={bw} height={Math.max(2, y(0) - y(d.flagged))} rx={4} />
              )}
            </g>
          );
        })}
        {labelIdx.map((i) => (
          <text key={i} x={left + slot * (i + 0.5)} y={H - 8} textAnchor={n > 1 && i === 0 ? "start" : n > 1 && i === n - 1 ? "end" : "middle"}>
            {shortDay(daily[i].day)}
          </text>
        ))}
      </svg>
      <div className="legend" style={{ marginTop: 8 }}>
        <span>
          <i className="box" style={{ background: "var(--rule-strong)" }} />
          Files scanned
        </span>
        <span>
          <i className="box" style={{ background: "var(--danger)" }} />
          Needed attention
        </span>
      </div>
    </div>
  );
}
