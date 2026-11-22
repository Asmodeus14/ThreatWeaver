import type { ScanResultDto } from "../lib/api";
import { thresholdsFrom, useStatus } from "../lib/detector";
import { ms } from "../lib/format";
import { verdictInfo } from "../lib/verdicts";
import { Verdict } from "./Verdict";
import { VerdictScale } from "./VerdictScale";

export function ResultsTable({
  rows,
  onOpen,
  showTime = true,
  caption,
}: {
  rows: ScanResultDto[];
  onOpen: (r: ScanResultDto) => void;
  showTime?: boolean;
  caption?: string;
}) {
  const status = useStatus();
  const thresholds = thresholdsFrom(status);
  const activeId = status?.detector?.id;
  return (
    <div className="table-wrap">
      <table className="results">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            <th>File</th>
            <th>Verdict</th>
            <th className="score-col">Score</th>
            <th>Analysed by</th>
            {showTime && <th className="num">Time</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const v = verdictInfo(r.verdict);
            const scored = !["unsupported", "error"].includes(v.key);
            return (
              <tr
                key={`${r.sha256}-${i}`}
                className="clickable"
                tabIndex={0}
                onClick={() => onOpen(r)}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), onOpen(r))}
              >
                <td>
                  <div className="file-cell">
                    <span>{r.file_name}</span>
                    <span className="path" title={r.file_path}>
                      {r.file_path}
                    </span>
                  </div>
                </td>
                <td>
                  <Verdict verdict={r.verdict} />
                </td>
                <td>
                  {scored ? (
                    <VerdictScale
                      micro
                      score={r.malware_probability}
                      tone={v.tone}
                      // Zones belong to the detector that set them; other models' scores get a plain track.
                      thresholds={activeId && (r.model_version || "").split(/[\s()]+/).includes(activeId) ? thresholds : null}
                    />
                  ) : (
                    <span className="muted small">—</span>
                  )}
                </td>
                <td className="xs muted mono by-col">{r.triage_stage ?? (r.model_version ? r.model_version.split(" ")[0] : "—")}</td>
                {showTime && <td className="num small muted time-col">{ms(r.scan_duration_ms)}</td>}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
