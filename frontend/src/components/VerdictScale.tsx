import { Thresholds } from "../lib/detector";
import { pct } from "../lib/format";

/**
 * The calibrated verdict scale: a file's P(malicious) drawn against the detector's two
 * real operating thresholds (chosen on validation data for 1% and 0.1% false-positive
 * rates). The bands are the policy, so the picture is the explanation.
 */
export function VerdictScale({
  score,
  thresholds,
  micro = false,
}: {
  score: number | null;
  thresholds: Thresholds | null;
  micro?: boolean;
}) {
  const lo = thresholds?.low ?? 0.5;
  const hi = thresholds?.high ?? 0.5;
  const style = { "--lo": `${lo * 100}%`, "--hi": `${hi * 100}%` } as React.CSSProperties;
  const label = score === null ? "No score" : `Score ${pct(score)}; review threshold ${pct(lo)}; high-confidence threshold ${pct(hi)}`;
  return (
    <div className={`vscale${micro ? " micro" : ""}`} role="img" aria-label={label} title={micro ? label : undefined}>
      <div className="vscale-track" style={style}>
        {thresholds && <div className="vscale-thr" style={{ left: `${lo * 100}%` }} />}
        {thresholds && thresholds.high !== thresholds.low && <div className="vscale-thr" style={{ left: `${hi * 100}%` }} />}
        {score !== null && <div className="vscale-tick" style={{ left: `${Math.max(0, Math.min(1, score)) * 100}%` }} />}
      </div>
      {!micro && thresholds && (
        <div className="vscale-legend">
          <span>
            <i className="band review" />
            Review from {pct(lo)} ({thresholds.lowLabel})
          </span>
          {thresholds.high !== thresholds.low && (
            <span>
              <i className="band high" />
              High confidence from {pct(hi)} ({thresholds.highLabel})
            </span>
          )}
        </div>
      )}
    </div>
  );
}
