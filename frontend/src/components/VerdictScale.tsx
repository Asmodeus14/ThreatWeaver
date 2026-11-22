import { Thresholds } from "../lib/detector";
import { pct } from "../lib/format";

export type Zone = "low" | "review" | "high";

export function zoneOf(score: number, t: Thresholds | null): Zone {
  if (!t) return score >= 0.5 ? "review" : "low";
  if (score >= t.high && t.high !== t.low) return "high";
  if (score >= t.low) return "review";
  return "low";
}

const ZONE_TONE: Record<Zone, string> = { low: "tone-ok", review: "tone-warning", high: "tone-danger" };

/**
 * The calibrated score gauge: a file's P(malicious) placed on the detector's real
 * operating zones. Below review / review (from the 1% FPR threshold) / high confidence
 * (from the 0.1% FPR threshold). Zones come from /api/status, never from constants.
 */
export function VerdictScale({
  score,
  thresholds,
  micro = false,
  tone,
}: {
  score: number | null;
  thresholds: Thresholds | null;
  micro?: boolean;
  /** Colour of the marker and value; the file's verdict tone (zones only shade the track). */
  tone?: string;
}) {
  const lo = thresholds?.low ?? 0.5;
  const hi = thresholds?.high ?? lo;
  const twoZones = !!thresholds && hi !== lo;
  const s = score === null ? null : Math.max(0, Math.min(1, score));
  const zone = s === null ? null : zoneOf(s, thresholds);
  const zoneText =
    zone === "high" ? "in the high-confidence zone" : zone === "review" ? "in the review zone" : zone === "low" ? "below the review threshold" : "";
  const label =
    s === null
      ? "No score"
      : `Score ${pct(s)}, ${zoneText}. Review threshold ${pct(lo)}${thresholds ? ` (${thresholds.lowLabel})` : ""}` +
        (twoZones ? `; high-confidence threshold ${pct(hi)} (${thresholds!.highLabel})` : "");
  const markTone = tone ? `tone-${tone}` : thresholds && zone ? ZONE_TONE[zone] : "tone-muted";
  const style = { "--lo": `${lo * 100}%`, "--hi": `${hi * 100}%` } as React.CSSProperties;

  const track = (
    <div className="gauge-track" style={style}>
      {thresholds && <span className="gauge-zone low" />}
      {thresholds && <span className="gauge-zone review" />}
      {twoZones && <span className="gauge-zone high" />}
      {thresholds && <span className="gauge-thr" style={{ left: `${lo * 100}%` }} />}
      {twoZones && <span className="gauge-thr" style={{ left: `${hi * 100}%` }} />}
      {s !== null && <span className={`gauge-marker ${markTone}`} style={{ left: `${s * 100}%` }} />}
    </div>
  );

  if (micro) {
    return (
      <div className="gauge compact" role="img" aria-label={label} title={label}>
        {track}
        <span className={`gauge-value ${s === null ? "muted" : markTone}`}>{s === null ? "—" : pct(s)}</span>
      </div>
    );
  }

  // Keep the bubble inside the track at the extremes.
  const bubbleLeft = s === null ? 0 : Math.min(94, Math.max(6, s * 100));
  return (
    <div className="gauge full" role="img" aria-label={label}>
      {s !== null && (
        <span className={`gauge-bubble ${markTone}`} style={{ left: `${bubbleLeft}%` }}>
          <span>{pct(s)}</span>
        </span>
      )}
      {track}
      <div className="gauge-axis" aria-hidden="true">
        <span>0%</span>
        <span>25%</span>
        <span>50%</span>
        <span>75%</span>
        <span>100%</span>
      </div>
      {thresholds && (
        <div className="gauge-zones">
          <div className="zone-card" data-active={zone === "low"}>
            <b>
              <i className="zone-low-swatch" />
              Below review
            </b>
            <span className="range">0 – {pct(lo)}</span>
          </div>
          <div className="zone-card" data-active={zone === "review"}>
            <b>
              <i className="zone-review-swatch" />
              Review
            </b>
            <span className="range">
              {pct(lo)}
              {twoZones ? ` – ${pct(hi)}` : " and above"}
            </span>
            <span>{thresholds.lowLabel}</span>
          </div>
          {twoZones && (
            <div className="zone-card" data-active={zone === "high"}>
              <b>
                <i className="zone-high-swatch" />
                High confidence
              </b>
              <span className="range">{pct(hi)} and above</span>
              <span>{thresholds.highLabel}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
