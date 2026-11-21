import type { ScanResultDto } from "../lib/api";
import { thresholdsFrom, useStatus } from "../lib/detector";
import { ms, pct } from "../lib/format";
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
  const thresholds = thresholdsFrom(useStatus());
  return (
    <div className="table-wrap">
      <table>
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            <th>File</th>
            <th>Verdict</th>
            <th>Score</th>
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
                    <div className="row" style={{ flexWrap: "nowrap" }}>
                      <VerdictScale micro score={r.malware_probability} thresholds={thresholds} />
                      <span className="small">{pct(r.malware_probability)}</span>
                    </div>
                  ) : (
                    <span className="muted small">—</span>
                  )}
                </td>
                <td className="small muted">{r.triage_stage ?? r.model_version.split(" ")[0]}</td>
                {showTime && <td className="num small muted">{ms(r.scan_duration_ms)}</td>}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
