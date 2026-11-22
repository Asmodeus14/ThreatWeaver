import { useState } from "react";
import { api } from "../lib/api";
import { useApi } from "../lib/useApi";
import { Async, Empty } from "../components/States";
import { useToast } from "../components/Toast";

interface QueueItem {
  id: string;
  file_name: string;
  file_path: string;
  sha256: string;
  assigned_label: number;
  family_name: string;
  detected_verdict: string;
  added_at: string;
  status: string;
}
interface Prototype {
  label: number;
  label_name: string;
  family_name: string;
  sample_count: number;
  dimension: number;
}

export function Learning() {
  const queue = useApi<{ items: QueueItem[]; pending_count: number; last_report: Record<string, unknown> | null }>("/api/learning/queue");
  const protos = useApi<{ prototypes: Prototype[]; novelty_threshold: number }>("/api/learning/prototypes");
  const toast = useToast();
  const [persist, setPersist] = useState(false);
  const [busy, setBusy] = useState(false);

  async function adapt() {
    if (!window.confirm(`Fine-tune the legacy neural model on ${queue.data?.pending_count ?? 0} queued file(s)?${persist ? "\n\nThe result is saved as a new local model version; the shipped model is never overwritten." : ""}`)) return;
    setBusy(true);
    try {
      const r = await api.post<{ status: string; saved_checkpoint?: string }>("/api/learning/adapt", { persist });
      toast(r.saved_checkpoint ? `Adapted and saved ${r.saved_checkpoint}.` : "Adaptation finished (not saved).");
      queue.reload();
      protos.reload();
    } catch (e) {
      toast((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    await api.del(`/api/learning/queue?id=${encodeURIComponent(id)}`).catch((e) => toast(e.message, true));
    queue.reload();
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Learning</h1>
          <p>Files you label from detection details wait here. Adaptation applies to the legacy neural model only.</p>
        </div>
        <div className="row">
          <label className="row small">
            <input type="checkbox" checked={persist} onChange={(e) => setPersist(e.target.checked)} />
            Save as a new local model version
          </label>
          <button className="primary" disabled={busy || !queue.data?.pending_count} onClick={adapt}>
            Adapt now
          </button>
        </div>
      </div>
      <p className="note synthetic">
        In-app adaptation currently replays a small synthetic seed set to limit forgetting; gated retraining on real EMBER2024 data is planned (roadmap 7.1).
        The LightGBM detector is not changed by this page.
      </p>

      <section className="section">
        <h2>Queue</h2>
        <Async
          state={queue}
          empty={(q) =>
            q.items.length === 0 ? (
              <div className="panel">
                <Empty title="Nothing queued">Open a detection and choose “Queue as malicious” or “Queue as benign”.</Empty>
              </div>
            ) : null
          }
        >
          {(q) => (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Your label</th>
                    <th>Original verdict</th>
                    <th>Added</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {q.items.map((i) => (
                    <tr key={i.id}>
                      <td>
                        <div className="file-cell">
                          <span>{i.file_name}</span>
                          <span className="path">{i.file_path}</span>
                        </div>
                      </td>
                      <td>{i.assigned_label ? "Malicious" : "Benign"}</td>
                      <td className="small">{i.detected_verdict}</td>
                      <td className="small">{i.added_at.replace("T", " ").slice(0, 19)}</td>
                      <td className="small">{i.status}</td>
                      <td>
                        <button className="ghost" onClick={() => remove(i.id)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Async>
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Similarity prototypes</h2>
          <span className="hint">Cluster centroids used by the legacy novelty check</span>
        </div>
        <Async state={protos} empty={(p) => (p.prototypes.length === 0 ? <Empty title="No prototypes loaded" /> : null)}>
          {(p) => (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Cluster</th>
                    <th>Class</th>
                    <th className="num">Training samples</th>
                    <th className="num">Dimensions</th>
                  </tr>
                </thead>
                <tbody>
                  {p.prototypes.map((x) => (
                    <tr key={x.family_name}>
                      <td>{x.family_name}</td>
                      <td>{x.label_name}</td>
                      <td className="num">{x.sample_count}</td>
                      <td className="num">{x.dimension}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Async>
      </section>
    </>
  );
}
