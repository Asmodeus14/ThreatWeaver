import { api, QuarantineEntry } from "../lib/api";
import { bytes, shortHash } from "../lib/format";
import { useApi } from "../lib/useApi";
import { Async, Empty } from "../components/States";
import { useToast } from "../components/Toast";

export function Quarantine() {
  const q = useApi<{ entries: QuarantineEntry[] }>("/api/quarantine");
  const toast = useToast();

  async function restore(e: QuarantineEntry) {
    if (!window.confirm(`Restore ${e.original_filename} to\n${e.original_path}?\n\nOnly restore files you have confirmed are safe.`)) return;
    try {
      const r = await api.post<{ restored_path: string }>("/api/restore", { quarantine_id: e.quarantine_id });
      toast(`Restored to ${r.restored_path}.`);
      q.reload();
    } catch (err) {
      toast((err as Error).message, true);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Quarantine</h1>
          <p>
            Quarantined files are stored XOR-masked so they cannot run by accident. This is neutralisation, not encryption. Each restore is
            hash-verified against the original.
          </p>
        </div>
        <button onClick={q.reload}>Refresh</button>
      </div>
      <Async
        state={q}
        empty={(d) =>
          d.entries.length === 0 ? (
            <div className="panel">
              <Empty title="The vault is empty">Quarantine a file from its detection details.</Empty>
            </div>
          ) : null
        }
      >
        {(d) => (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>File</th>
                  <th>Quarantined</th>
                  <th>Reason</th>
                  <th className="num">Size</th>
                  <th>SHA-256</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {[...d.entries].reverse().map((e) => (
                  <tr key={e.quarantine_id}>
                    <td>
                      <div className="file-cell">
                        <span>{e.original_filename}</span>
                        <span className="path">{e.original_path}</span>
                      </div>
                    </td>
                    <td className="small">{e.quarantined_at}</td>
                    <td className="small">{e.reason}</td>
                    <td className="num small">{bytes(e.file_size_bytes)}</td>
                    <td className="mono small">{shortHash(e.sha256)}</td>
                    <td className="small">{e.restored ? `Restored ${e.restored_at ?? ""}` : "Isolated"}</td>
                    <td>{!e.restored && <button onClick={() => restore(e)}>Restore</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Async>
    </>
  );
}
