import type { HistoryRecord } from "../lib/api";
import { num } from "../lib/format";
import { go } from "../lib/router";
import { useApi } from "../lib/useApi";
import { Async, Empty } from "../components/States";

export function Reports() {
  const h = useApi<{ history: HistoryRecord[] }>("/api/history");
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scan history</h1>
          <p>Every saved scan, newest first. Open Detections to search individual files across all of them.</p>
        </div>
        <button onClick={() => go("detections", {})}>Search files</button>
      </div>
      <Async
        state={h}
        empty={(d) =>
          d.history.length === 0 ? (
            <div className="panel">
              <Empty title="No scans saved yet" />
            </div>
          ) : null
        }
      >
        {(d) => (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Target</th>
                  <th className="num">Files</th>
                  <th className="num">Malicious</th>
                  <th className="num">Suspicious</th>
                  <th className="num">Unfamiliar</th>
                  <th className="num">Errors</th>
                  <th className="num">Duration</th>
                </tr>
              </thead>
              <tbody>
                {[...d.history].reverse().map((r) => {
                  const s = r.summary || {};
                  return (
                    <tr key={r.scan_id}>
                      <td className="small">{r.timestamp}</td>
                      <td className="small mono" style={{ maxWidth: 380, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.target_path}>
                        {r.target_path}
                      </td>
                      <td className="num">{num(s.total_scanned)}</td>
                      <td className="num tone-danger">{num((s.known_malicious ?? 0) + (s.likely_malicious ?? 0))}</td>
                      <td className="num">{num(s.suspicious)}</td>
                      <td className="num">{num(s.unfamiliar)}</td>
                      <td className="num">{num(s.analysis_errors)}</td>
                      <td className="num small">{num(r.duration_seconds, 1)} s</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Async>
    </>
  );
}
