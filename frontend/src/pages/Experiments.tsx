import type { Ablation, Timeline } from "../lib/api";
import { useStatus } from "../lib/detector";
import { num, pct } from "../lib/format";
import { useApi } from "../lib/useApi";
import { Async, Empty } from "../components/States";

const STRATEGY: Record<string, string> = {
  none: "No replay (plain fine-tuning)",
  random: "Random replay",
  uncertainty: "Uncertainty replay",
  uncertainty_diversity: "Uncertainty and diversity replay",
};

export function Experiments() {
  const status = useStatus();
  const ablation = useApi<Ablation>("/api/embedding-ablation");
  const timeline = useApi<Timeline>("/api/timeline");

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Experiments</h1>
          <p>Research results recorded in this repository, with their sources. Older results use the v0.1 feature set.</p>
        </div>
      </div>

      <section className="section">
        <h2>Loaded neural model</h2>
        <dl className="facts">
          <div className="fact">
            <dt>Architecture</dt>
            <dd>{status?.model_kind ?? "—"}</dd>
            <div className="sub">
              {status?.residual_blocks ?? "—"} residual blocks, {status?.embedding_dim ?? "—"}-D embedding
            </div>
          </div>
          <div className="fact">
            <dt>Temperature</dt>
            <dd>{num(status?.temperature, 3)}</dd>
            <div className="sub">fitted on validation logits</div>
          </div>
          <div className="fact">
            <dt>Novelty threshold</dt>
            <dd>{num(status?.novelty_threshold, 4)}</dd>
            <div className="sub">cosine distance to prototypes</div>
          </div>
        </dl>
        <p className="note">{status?.architecture}</p>
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Embedding dimension study</h2>
          <span className="hint">artifacts/benchmarks/embedding_dimension_results.json</span>
        </div>
        <Async
          state={ablation}
          empty={(a) =>
            !a.results?.summary_table?.length ? (
              <div className="panel">
                <Empty title="No ablation results">{a.status}</Empty>
              </div>
            ) : null
          }
        >
          {(a) => {
            const rows = a.results!.summary_table;
            const cols = Object.keys(rows[0]);
            const sel = a.selection?.selected_best_dimension;
            const md = a.results!.metadata as Record<string, number | number[]>;
            return (
              <>
                <p className="note">
                  {(md.dimensions_evaluated as number[])?.length} dimensions, {(md.seeds_evaluated as number[])?.length} seeds; {String(md.samples_train)} training and{" "}
                  {String(md.samples_test)} test samples. Values are mean ± SD across seeds; most differences are within one SD, so no dimension is a clear winner.
                </p>
                <div className="table-wrap nowrap">
                  <table>
                    <thead>
                      <tr>
                        {cols.map((c) => (
                          <th key={c}>{c}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((r) => (
                        <tr key={String(r.Dimension)} style={r.Dimension === sel ? { fontWeight: 600 } : undefined}>
                          {cols.map((c) => (
                            <td key={c} className="small">
                              {String(r[c])}
                              {c === "Dimension" && r.Dimension === sel ? " (shipped)" : ""}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            );
          }}
        </Async>
      </section>

      <section className="section">
        <h2>Continual learning without forgetting</h2>
        <Async
          state={timeline}
          empty={(t) =>
            !t.available ? (
              <div className="panel">
                <Empty title="No continual-learning results">{t.reason}</Empty>
              </div>
            ) : null
          }
        >
          {(t) => <ContinualView t={t} />}
        </Async>
      </section>
    </>
  );
}

function ContinualView({ t }: { t: Timeline }) {
  const entries = Object.entries(t.strategies ?? {});
  const best = entries.reduce<string | null>((b, [k, v]) => (b === null || v.forgetting_mean < (t.strategies![b].forgetting_mean ?? 1) ? k : b), null);
  return (
    <>
      <p className={`note${t.kind === "synthetic" ? " synthetic" : ""}`}>
        {t.kind === "synthetic" ? "Synthetic data. " : ""}
        {t.dataset} Source: <code>{t.source}</code>. {(t.caveats ?? []).join(" ")}
      </p>
      {t.batches && t.batches.length > 0 && (
        <ol className="row small" style={{ listStyle: "none", padding: 0, margin: 0, gap: 0 }} aria-label="Training batches in time order">
          {t.batches.map((b, i) => (
            <li key={b.batch_id} style={{ flex: 1, borderTop: "2px solid var(--rule-strong)", paddingTop: 6, paddingRight: 8 }}>
              <strong>{b.batch_id}</strong>
              <div className="muted xs">
                {b.window_start} to {b.window_end}
              </div>
              {i === 0 && <div className="xs muted">first training batch</div>}
            </li>
          ))}
        </ol>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Strategy</th>
              <th className="num">Forgetting</th>
              <th className="num">Backward transfer</th>
              <th className="num">Final macro-F1</th>
              <th className="num">Final FPR</th>
              <th className="num">Training time</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([k, v]) => (
              <tr key={k} style={k === best ? { fontWeight: 600 } : undefined}>
                <td>
                  {STRATEGY[k] ?? k}
                  {k === best ? " (least forgetting)" : ""}
                </td>
                <td className="num">{num(v.forgetting_mean, 4)}</td>
                <td className="num">{num(v.bwt_mean, 4)}</td>
                <td className="num">{num(v.macro_f1_mean, 4)}</td>
                <td className="num">{pct(v.fpr_mean, 2)}</td>
                <td className="num">{num(v.time_sec_mean, 1)} s</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {entries[0]?.[1].r_matrix && <RMatrix entries={entries} />}
    </>
  );
}

/** Accuracy on each earlier batch (columns) after training on each batch (rows). */
function RMatrix({ entries }: { entries: [string, { r_matrix?: number[][] }][] }) {
  return (
    <div className="grid-2">
      {entries.map(([k, v]) => {
        const m = v.r_matrix!;
        const vals = m.flatMap((r, i) => r.slice(0, i + 1));
        const lo = Math.min(...vals);
        return (
          <figure key={k} className="panel panel-pad" style={{ margin: 0 }}>
            <figcaption className="small" style={{ marginBottom: 8 }}>
              {STRATEGY[k] ?? k}: macro-F1 on batch (column) after training through batch (row)
            </figcaption>
            <table style={{ fontSize: 12 }}>
              <tbody>
                {m.map((row, i) => (
                  <tr key={i}>
                    <th scope="row" style={{ padding: "4px 8px" }}>
                      T{i + 1}
                    </th>
                    {row.map((val, j) => {
                      const shown = j <= i;
                      const a = shown ? (val - lo) / Math.max(1 - lo, 1e-6) : 0;
                      return (
                        <td
                          key={j}
                          style={{
                            padding: "4px 8px",
                            textAlign: "center",
                            background: shown ? `color-mix(in srgb, var(--signal) ${Math.round(15 + a * 55)}%, var(--surface))` : "transparent",
                            color: shown ? "var(--ink)" : "var(--faint)",
                          }}
                        >
                          {shown ? val.toFixed(3) : ""}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </figure>
        );
      })}
    </div>
  );
}
