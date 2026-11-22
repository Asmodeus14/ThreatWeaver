import { useMemo, useState } from "react";
import type { FamiliesResponse } from "../lib/api";
import { num, pct } from "../lib/format";
import { useApi } from "../lib/useApi";
import { Async, Empty } from "../components/States";

const top = (o: Record<string, number> | undefined, n = 3) =>
  Object.entries(o ?? {})
    .slice(0, n)
    .map(([k, v]) => `${k} (${num(v)})`)
    .join(", ");

export function Families() {
  const fams = useApi<FamiliesResponse>("/api/families");
  const [filter, setFilter] = useState("");

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Malware families</h1>
          <p>Families counted from the EMBER2024 metadata on disk. Labels come from the dataset (antivirus consensus), not from ThreatWeaver's model.</p>
        </div>
        <input type="search" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter families" aria-label="Filter families" />
      </div>
      <Async
        state={fams}
        empty={(d) =>
          !d.available || d.families.length === 0 ? (
            <div className="panel">
              <Empty title="No family summary yet">{d.reason ?? "Run tools/build_family_summary.py to count families from the dataset."}</Empty>
            </div>
          ) : null
        }
      >
        {(d) => <FamilyTable d={d} filter={filter} />}
      </Async>
    </>
  );
}

function FamilyTable({ d, filter }: { d: FamiliesResponse; filter: string }) {
  const rows = useMemo(() => d.families.filter((f) => f.name.toLowerCase().includes(filter.toLowerCase())), [d, filter]);
  const max = Math.max(...d.families.map((f) => f.sample_count), 1);
  return (
    <>
      <p className="note">
        {num(d.distinct_families)} families with label confidence of at least {pct(d.min_family_confidence, 0)}; {num(d.totals?.malicious_with_family)} of{" "}
        {num(d.totals?.unique_malicious ?? d.totals?.malicious)} malicious samples carry a confident family label. Showing the {d.families.length} largest.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Family</th>
              <th className="num">Samples</th>
              <th style={{ width: 160 }}>Share of largest</th>
              <th className="num">Label confidence</th>
              <th>Seen</th>
              <th>File types</th>
              <th>Behaviour tags</th>
              <th>Packers</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.id}>
                <td>{f.name}</td>
                <td className="num">{num(f.sample_count)}</td>
                <td>
                  <div className="progress" aria-hidden="true">
                    <span style={{ width: `${(f.sample_count / max) * 100}%`, background: "var(--slate)" }} />
                  </div>
                </td>
                <td className="num">{pct(f.mean_family_confidence, 0)}</td>
                <td className="small muted">
                  {f.first_seen ?? "—"} to {f.last_seen ?? "—"}
                </td>
                <td className="small">{top(f.file_types)}</td>
                <td className="small">{top(f.tags?.behavior) || "—"}</td>
                <td className="small">{top(f.tags?.packer) || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
