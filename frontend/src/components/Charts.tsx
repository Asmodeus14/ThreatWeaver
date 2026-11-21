import { useMemo, useRef, useState } from "react";

export interface Series {
  name: string;
  x: number[];
  y: number[];
  color: string;
  dashed?: boolean;
}

interface Tip {
  left: number;
  top: number;
  text: string;
}

const W = 560;
const H = 300;
const M = { l: 48, r: 16, t: 12, b: 40 };

function ticks(min: number, max: number, n = 5) {
  return Array.from({ length: n + 1 }, (_, i) => min + ((max - min) * i) / n);
}

/**
 * Line chart for curves (ROC, PR, drift). `logX` maps x on a log10 scale (useful for ROC at
 * the 0.01–1% FPR range that matters for anti-malware); points with x <= 0 are clamped.
 */
export function LineChart({
  series,
  xLabel,
  yLabel,
  xDomain = [0, 1],
  yDomain = [0, 1],
  logX = false,
  xFormat = (v: number) => v.toFixed(2),
  yFormat = (v: number) => v.toFixed(2),
  markers = [],
  diagonal = false,
  ariaLabel,
}: {
  series: Series[];
  xLabel: string;
  yLabel: string;
  xDomain?: [number, number];
  yDomain?: [number, number];
  logX?: boolean;
  xFormat?: (v: number) => string;
  yFormat?: (v: number) => string;
  markers?: { x: number; y: number; label: string }[];
  diagonal?: boolean;
  ariaLabel: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<Tip | null>(null);
  const [x0, x1] = logX ? [Math.log10(Math.max(xDomain[0], 1e-5)), Math.log10(xDomain[1])] : xDomain;
  const sx = (v: number) => {
    const t = logX ? Math.log10(Math.max(v, xDomain[0], 1e-5)) : v;
    return M.l + ((t - x0) / (x1 - x0)) * (W - M.l - M.r);
  };
  const sy = (v: number) => H - M.b - ((v - yDomain[0]) / (yDomain[1] - yDomain[0])) * (H - M.t - M.b);
  const xTicks = logX
    ? Array.from({ length: Math.round(x1 - x0) + 1 }, (_, i) => 10 ** (x0 + i))
    : ticks(xDomain[0], xDomain[1]);
  const yTicks = ticks(yDomain[0], yDomain[1]);

  const paths = useMemo(
    () =>
      series.map((s) => {
        const pts = s.x.map((x, i) => [sx(x), sy(s.y[i])] as const).filter(([a, b]) => isFinite(a) && isFinite(b));
        return { s, d: pts.map(([a, b], i) => `${i ? "L" : "M"}${a.toFixed(1)},${b.toFixed(1)}`).join("") };
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [series, logX, xDomain[0], xDomain[1], yDomain[0], yDomain[1]],
  );

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const box = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
    const px = ((e.clientX - box.left) / box.width) * W;
    let best: { d: number; s: Series; i: number } | null = null;
    for (const s of series) {
      for (let i = 0; i < s.x.length; i++) {
        const d = Math.abs(sx(s.x[i]) - px);
        if (!best || d < best.d) best = { d, s, i };
      }
    }
    if (!best || best.d > 20) return setTip(null);
    const { s, i } = best;
    setTip({
      left: (sx(s.x[i]) / W) * box.width,
      top: (sy(s.y[i]) / H) * box.height,
      text: `${s.name}: ${xLabel} ${xFormat(s.x[i])}, ${yLabel} ${yFormat(s.y[i])}`,
    });
  }

  return (
    <div className="chart" ref={ref}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={ariaLabel} onMouseMove={onMove} onMouseLeave={() => setTip(null)}>
        {yTicks.map((t) => (
          <g key={`y${t}`}>
            <line className="grid" x1={M.l} x2={W - M.r} y1={sy(t)} y2={sy(t)} />
            <text x={M.l - 6} y={sy(t) + 4} textAnchor="end">
              {yFormat(t)}
            </text>
          </g>
        ))}
        {xTicks.map((t) => (
          <text key={`x${t}`} x={sx(t)} y={H - M.b + 16} textAnchor="middle">
            {xFormat(t)}
          </text>
        ))}
        <line className="axis" x1={M.l} x2={W - M.r} y1={H - M.b} y2={H - M.b} />
        <line className="axis" x1={M.l} x2={M.l} y1={M.t} y2={H - M.b} />
        {diagonal && (
          <line x1={sx(xDomain[0])} y1={sy(yDomain[0])} x2={sx(xDomain[1])} y2={sy(yDomain[1])} stroke="var(--rule-strong)" strokeDasharray="3 3" />
        )}
        {paths.map(({ s, d }) => (
          <path key={s.name} d={d} fill="none" stroke={s.color} strokeWidth={1.8} strokeDasharray={s.dashed ? "4 3" : undefined} />
        ))}
        {markers.map((m) => (
          <g key={m.label}>
            <circle cx={sx(m.x)} cy={sy(m.y)} r={4} fill="var(--surface)" stroke="var(--ink)" strokeWidth={1.5} />
            <text x={sx(m.x) + 7} y={sy(m.y) + 14} fill="var(--ink)">
              {m.label}
            </text>
          </g>
        ))}
        <text x={(M.l + W - M.r) / 2} y={H - 6} textAnchor="middle">
          {xLabel}
          {logX ? " (log scale)" : ""}
        </text>
        <text x={12} y={(M.t + H - M.b) / 2} textAnchor="middle" transform={`rotate(-90 12 ${(M.t + H - M.b) / 2})`}>
          {yLabel}
        </text>
      </svg>
      {tip && (
        <div className="chart-tip" style={{ left: tip.left, top: tip.top }}>
          {tip.text}
        </div>
      )}
      <div className="legend">
        {series.map((s) => (
          <span key={s.name}>
            <i style={{ background: s.color }} />
            {s.name}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Grouped bars over equal-width bins (score histograms, reliability diagram). */
export function BarChart({
  bins,
  groups,
  xLabel,
  yLabel,
  yFormat = (v: number) => String(Math.round(v)),
  logY = false,
  overlayLine,
  ariaLabel,
}: {
  bins: { lo: number; hi: number }[];
  groups: { name: string; values: number[]; color: string }[];
  xLabel: string;
  yLabel: string;
  yFormat?: (v: number) => string;
  logY?: boolean;
  overlayLine?: { name: string; values: number[]; color: string };
  ariaLabel: string;
}) {
  const [tip, setTip] = useState<Tip | null>(null);
  const tf = (v: number) => (logY ? Math.log10(1 + v) : v);
  const max = Math.max(1e-9, ...groups.flatMap((g) => g.values.map(tf)), ...(overlayLine ? overlayLine.values.map(tf) : []));
  const bw = (W - M.l - M.r) / Math.max(bins.length, 1);
  const gw = (bw - 4) / Math.max(groups.length, 1);
  const sy = (v: number) => H - M.b - (tf(v) / max) * (H - M.t - M.b);
  const yTicks = ticks(0, max, 4);
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={ariaLabel} onMouseLeave={() => setTip(null)}>
        {yTicks.map((t) => (
          <g key={t}>
            <line className="grid" x1={M.l} x2={W - M.r} y1={H - M.b - (t / max) * (H - M.t - M.b)} y2={H - M.b - (t / max) * (H - M.t - M.b)} />
            <text x={M.l - 6} y={H - M.b - (t / max) * (H - M.t - M.b) + 4} textAnchor="end">
              {yFormat(logY ? 10 ** t - 1 : t)}
            </text>
          </g>
        ))}
        {bins.map((b, i) =>
          groups.map((g, gi) => {
            const v = g.values[i] ?? 0;
            const x = M.l + i * bw + 2 + gi * gw;
            return (
              <rect
                key={`${i}-${g.name}`}
                x={x}
                y={sy(v)}
                width={Math.max(gw - 1, 1)}
                height={H - M.b - sy(v)}
                fill={g.color}
                onMouseMove={(e) => {
                  const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
                  setTip({
                    left: ((x + gw / 2) / W) * box.width,
                    top: (sy(v) / H) * box.height,
                    text: `${g.name}, ${b.lo.toFixed(2)}–${b.hi.toFixed(2)}: ${yFormat(v)}`,
                  });
                }}
              />
            );
          }),
        )}
        {overlayLine && (
          <path
            d={overlayLine.values.map((v, i) => `${i ? "L" : "M"}${M.l + i * bw + bw / 2},${sy(v)}`).join("")}
            fill="none"
            stroke={overlayLine.color}
            strokeWidth={1.6}
            strokeDasharray="4 3"
          />
        )}
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <text key={t} x={M.l + t * (W - M.l - M.r)} y={H - M.b + 16} textAnchor="middle">
            {t.toFixed(2)}
          </text>
        ))}
        <line className="axis" x1={M.l} x2={W - M.r} y1={H - M.b} y2={H - M.b} />
        <text x={(M.l + W - M.r) / 2} y={H - 6} textAnchor="middle">
          {xLabel}
        </text>
        <text x={12} y={(M.t + H - M.b) / 2} textAnchor="middle" transform={`rotate(-90 12 ${(M.t + H - M.b) / 2})`}>
          {yLabel}
          {logY ? " (log)" : ""}
        </text>
      </svg>
      {tip && (
        <div className="chart-tip" style={{ left: tip.left, top: tip.top }}>
          {tip.text}
        </div>
      )}
      <div className="legend">
        {groups.map((g) => (
          <span key={g.name}>
            <i className="box" style={{ background: g.color }} />
            {g.name}
          </span>
        ))}
        {overlayLine && (
          <span>
            <i style={{ background: overlayLine.color }} />
            {overlayLine.name}
          </span>
        )}
      </div>
    </div>
  );
}
