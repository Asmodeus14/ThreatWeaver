import { useEffect, useState } from "react";
import type { DetectionRow, ScanResultDto } from "../lib/api";
import { useRoute } from "../lib/router";
import { useApi } from "../lib/useApi";
import { DetectionDrawer } from "../components/DetectionDrawer";
import { ResultsTable } from "../components/ResultsTable";
import { Async, Empty } from "../components/States";

const FILTERS: { id: string; label: string; verdicts: string[] }[] = [
  { id: "attention", label: "Needs attention", verdicts: ["Known Malicious", "Likely Malicious", "Suspicious", "Unfamiliar / Out-of-Distribution", "Analysis Error"] },
  { id: "malicious", label: "Malicious", verdicts: ["Known Malicious", "Likely Malicious"] },
  { id: "suspicious", label: "Suspicious", verdicts: ["Suspicious"] },
  { id: "unfamiliar", label: "Unfamiliar", verdicts: ["Unfamiliar / Out-of-Distribution"] },
  { id: "clean", label: "Benign or trusted", verdicts: ["Likely Benign", "Trusted Signer"] },
  { id: "all", label: "All files", verdicts: [] },
];

function latestPerFile(rows: DetectionRow[]): ScanResultDto[] {
  const seen = new Set<string>();
  return (rows as unknown as ScanResultDto[]).filter((r) => {
    const k = r.sha256 || r.file_path;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function Detections() {
  const route = useRoute();
  const wanted = route.params.get("filter");
  const [filter, setFilter] = useState(
    wanted && FILTERS.some((x) => x.id === wanted) ? wanted : route.params.get("q") || route.params.get("sha") ? "all" : "attention",
  );
  const [text, setText] = useState(route.params.get("q") ?? route.params.get("sha") ?? "");
  const [query, setQuery] = useState(text);
  const [open, setOpen] = useState<ScanResultDto | null>(null);
  const [everyScan, setEveryScan] = useState(false);
  const f = FILTERS.find((x) => x.id === filter)!;
  const qs = [...f.verdicts.map((v) => `verdict=${encodeURIComponent(v)}`), query ? `q=${encodeURIComponent(query)}` : "", "limit=500"]
    .filter(Boolean)
    .join("&");
  const rows = useApi<{ results: DetectionRow[] }>(`/api/detections?${qs}`);
  const deepSha = route.params.get("sha");
  useEffect(() => {
    if (!deepSha || !rows.data) return;
    const hit = rows.data.results.find((r) => r.sha256.startsWith(deepSha.toLowerCase()));
    if (hit) setOpen(hit as unknown as ScanResultDto);
  }, [deepSha, rows.data]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Detections</h1>
          <p>Every file from your saved scans, newest first. Open one to see the evidence behind its verdict.</p>
        </div>
      </div>
      <div className="row">
        <div className="segmented" role="group" aria-label="Filter by verdict">
          {FILTERS.map((x) => (
            <button key={x.id} aria-pressed={filter === x.id} onClick={() => setFilter(x.id)}>
              {x.label}
            </button>
          ))}
        </div>
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault();
            setQuery(text.trim());
          }}
        >
          <input type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder="Path or SHA-256 prefix" aria-label="Filter by path or hash" />
          <button type="submit">Filter</button>
        </form>
        <label className="row small">
          <input type="checkbox" checked={everyScan} onChange={(e) => setEveryScan(e.target.checked)} />
          Show every scan of a file
        </label>
      </div>
      <Async
        state={rows}
        empty={(d) =>
          d.results.length === 0 ? (
            <div className="panel">
              <Empty title={query ? `Nothing matches “${query}”` : "No files in this view"}>
                {query ? "Try a shorter path fragment or the first characters of the hash." : "Run a scan to fill your history."}
              </Empty>
            </div>
          ) : null
        }
      >
        {(d) => <ResultsTable rows={everyScan ? (d.results as unknown as ScanResultDto[]) : latestPerFile(d.results)} onOpen={setOpen} showTime={false} />}
      </Async>
      {open && <DetectionDrawer result={open} onClose={() => setOpen(null)} />}
    </>
  );
}
