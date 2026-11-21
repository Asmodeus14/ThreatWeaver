import { useEffect, useState } from "react";
import type { BinaryReport, Ci, EvalDetail, EvalSummary } from "../lib/api";
import { num, pct } from "../lib/format";
import { useApi } from "../lib/useApi";
import { BarChart, LineChart } from "../components/Charts";
import { Async, Empty } from "../components/States";

const ci = (c: Ci | null | undefined, f = (v: number) => v.toFixed(3)) => (c ? `95% CI ${f(c.lo)}–${f(c.hi)}` : "");
const OP_LABEL: Record<string, string> = {
  "tau_low_fpr_1pct": "Review threshold (1% FPR on validation)",
  "tau_high_fpr_0.1pct": "High-confidence threshold (0.1% FPR on validation)",
  "default_0.5": "Fixed 0.5 threshold",
  "val_fpr_1pct": "1% FPR threshold from validation",
};

export function Performance() {
  const list = useApi<{ evals: EvalSummary[] }>("/api/eval");
  const [id, setId] = useState<string | null>(null);
  useEffect(() => {
    if (!id && list.data?.evals.length) {
      const preferred = list.data.evals.find((e) => e.id.startsWith("lgbm")) ?? list.data.evals[0];
      setId(preferred.id);
    }
  }, [list.data, id]);
  const detail = useApi<EvalDetail>(id ? `/api/eval/detail?id=${encodeURIComponent(id)}` : null);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Model performance</h1>
          <p>Measured on held-out data the models never trained on. Thresholds are chosen on validation data and applied unchanged to test.</p>
        </div>
        {list.data && list.data.evals.length > 0 && (
          <select value={id ?? ""} onChange={(e) => setId(e.target.value)} aria-label="Evaluation">
            {list.data.evals.map((e) => (
              <option key={e.id} value={e.id}>
                {e.id} ({e.kind})
              </option>
            ))}
          </select>
        )}
      </div>
      <Async
        state={list}
        empty={(d) =>
          d.evals.length === 0 ? (
            <div className="panel">
              <Empty title="No evaluations found">Train a model with tools/train_lgbm.py; its eval.json appears here.</Empty>
            </div>
          ) : null
        }
      >
        {() => (detail.data ? <EvalView d={detail.data} /> : <Async state={detail}>{(d) => <EvalView d={d} />}</Async>)}
      </Async>
    </>
  );
}

function EvalView({ d }: { d: EvalDetail }) {
  const t = d.splits.test as BinaryReport | undefined;
  const [logRoc, setLogRoc] = useState(true);
  if (!t || !t.roc_curve) return <Empty title="This evaluation has no test curves" />;
  const caveats = (d.caveats as string[] | undefined) ?? [];
  const ops = Object.entries(t.operating_points ?? {});
  const markers = ops.map(([k, o]) => ({ x: Math.max(o.fpr, 1e-4), y: o.tpr, label: k.includes("high") ? "high" : k.includes("low") || k.includes("1pct") ? "review" : "0.5" }));
  const chal = d.splits.challenge as unknown as { n: number; detection_at: Record<string, number> } | undefined;
  const comp = d.comparison_with_lightgbm as Record<string, Record<string, { value: number; ci95: Ci }>> | undefined;
  const drift = t.drift_tau_low ?? [];
  const byType = (t as unknown as { by_file_type?: Record<string, BinaryReport> }).by_file_type;
  const dsTypes = (d.dataset as { file_types?: string[] }).file_types;

  return (
    <>
      <div className="row small muted">
        <span className={d.kind === "synthetic" ? "tag warn" : "tag"}>{d.kind}</span>
        <span>Created {d.created_utc}</span>
        <span>{d._signature}</span>
        {dsTypes && <span>Trained on {dsTypes.join(" and ")}</span>}
      </div>
      {caveats.length > 0 && (
        <div className="section">
          {caveats.map((c) => (
            <p key={c} className="note">{c}</p>
          ))}
        </div>
      )}

      <dl className="facts">
        <div className="fact">
          <dt>ROC-AUC</dt>
          <dd>{num(t.roc_auc, 4)}</dd>
          <div className="sub">{ci(t.ci95?.roc_auc, (v) => v.toFixed(4))}</div>
        </div>
        <div className="fact">
          <dt>Detected at 1% FPR</dt>
          <dd>{pct(t.tpr_at_fpr_curve?.["0.01"])}</dd>
          <div className="sub">{ci(t.ci95?.["tpr_at_fpr_0.01"], (v) => pct(v))}</div>
        </div>
        <div className="fact">
          <dt>Detected at 0.1% FPR</dt>
          <dd>{pct(t.tpr_at_fpr_curve?.["0.001"])}</dd>
          <div className="sub">{ci(t.ci95?.["tpr_at_fpr_0.001"], (v) => pct(v))}</div>
        </div>
        <div className="fact">
          <dt>Test samples</dt>
          <dd>{num(t.n)}</dd>
          <div className="sub">
            {num(t.n_malicious)} malicious, {num(t.n_benign)} benign
          </div>
        </div>
        <div className="fact">
          <dt>Calibration error</dt>
          <dd>{num(t.ece, 3)}</dd>
          <div className="sub">Brier {num(t.brier, 3)}</div>
        </div>
      </dl>

      {ops.length > 0 && (
        <section className="section">
          <h2>Operating points on test</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Threshold</th>
                  <th className="num">Score cut-off</th>
                  <th className="num">Malware detected</th>
                  <th className="num">False-positive rate</th>
                  <th className="num">Precision</th>
                  <th className="num">False positives / benign</th>
                </tr>
              </thead>
              <tbody>
                {ops.map(([k, o]) => (
                  <tr key={k}>
                    <td>{OP_LABEL[k] ?? k}</td>
                    <td className="num">{o.threshold.toFixed(4)}</td>
                    <td className="num">{pct(o.tpr)}</td>
                    <td className="num">{pct(o.fpr, 3)}</td>
                    <td className="num">{pct(o.precision, 2)}</td>
                    <td className="num">
                      {num(o.confusion.fp)} / {num(o.confusion.fp + o.confusion.tn)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {chal && (
            <p className="note">
              Evasive challenge set ({num(chal.n)} malware samples): {Object.entries(chal.detection_at).map(([k, v]) => `${pct(v)} detected at the ${OP_LABEL[k]?.split(" (")[0].toLowerCase() ?? k}`).join("; ")}.
            </p>
          )}
        </section>
      )}

      <div className="grid-2">
        <section className="section">
          <div className="section-head">
            <h2>ROC curve</h2>
            <label className="row small">
              <input type="checkbox" checked={logRoc} onChange={(e) => setLogRoc(e.target.checked)} />
              Log scale
            </label>
          </div>
          <div className="panel panel-pad">
            <LineChart
              ariaLabel="ROC curve: detection rate against false-positive rate"
              series={[{ name: "Test", x: t.roc_curve.x, y: t.roc_curve.y, color: "var(--signal)" }]}
              xLabel="False-positive rate"
              yLabel="Detection rate"
              logX={logRoc}
              xDomain={logRoc ? [1e-4, 1] : [0, 1]}
              xFormat={(v) => (v < 0.01 ? `${(v * 100).toFixed(2)}%` : `${(v * 100).toFixed(0)}%`)}
              yFormat={(v) => `${(v * 100).toFixed(0)}%`}
              markers={markers}
              diagonal={!logRoc}
            />
          </div>
        </section>
        {t.pr_curve && (
          <section className="section">
            <h2>Precision and recall</h2>
            <div className="panel panel-pad">
              <LineChart
                ariaLabel="Precision-recall curve"
                series={[{ name: "Test", x: t.pr_curve.x, y: t.pr_curve.y, color: "var(--signal)" }]}
                xLabel="Recall"
                yLabel="Precision"
                yDomain={[Math.max(0, Math.floor(Math.min(...t.pr_curve.y) * 10) / 10), 1]}
                xFormat={(v) => `${(v * 100).toFixed(0)}%`}
                yFormat={(v) => `${(v * 100).toFixed(0)}%`}
              />
            </div>
          </section>
        )}
        <section className="section">
          <h2>Score distribution</h2>
          <div className="panel panel-pad">
            <BarChart
              ariaLabel="Histogram of model scores for benign and malicious test files"
              bins={t.score_histogram.edges.slice(0, -1).map((lo, i) => ({ lo, hi: t.score_histogram.edges[i + 1] }))}
              groups={[
                { name: "Benign", values: t.score_histogram.benign, color: "var(--ok)" },
                { name: "Malicious", values: t.score_histogram.malicious, color: "var(--danger)" },
              ]}
              xLabel="Model score"
              yLabel="Files"
              logY
            />
          </div>
        </section>
        <section className="section">
          <h2>Calibration</h2>
          <div className="panel panel-pad">
            <BarChart
              ariaLabel="Reliability diagram: observed fraction malicious per score bin"
              bins={t.reliability.map((b) => ({ lo: b.lo, hi: b.hi }))}
              groups={[{ name: "Observed share malicious", values: t.reliability.map((b) => b.fraction_malicious), color: "var(--slate)" }]}
              overlayLine={{ name: "Perfect calibration", values: t.reliability.map((b) => (b.lo + b.hi) / 2), color: "var(--signal)" }}
              xLabel="Model score bin"
              yLabel="Share malicious"
              yFormat={(v) => `${Math.round(v * 100)}%`}
            />
          </div>
        </section>
      </div>

      {drift.length > 1 && (
        <section className="section">
          <div className="section-head">
            <h2>Over time</h2>
            <span className="hint">Test split in two-week windows, review threshold fixed</span>
          </div>
          <div className="panel panel-pad">
            <LineChart
              ariaLabel="Detection rate and false-positive rate per two-week window"
              series={[
                { name: "Detection rate", x: drift.map((_, i) => i), y: drift.map((r) => r.tpr), color: "var(--signal)" },
                { name: "False-positive rate", x: drift.map((_, i) => i), y: drift.map((r) => r.fpr), color: "var(--danger)", dashed: true },
              ]}
              xLabel="Window"
              yLabel="Rate"
              xDomain={[0, drift.length - 1]}
              xFormat={(v) => drift[Math.round(v)]?.period_start ?? ""}
              yFormat={(v) => `${(v * 100).toFixed(0)}%`}
            />
          </div>
        </section>
      )}

      {byType && Object.keys(byType).length > 0 && (
        <section className="section">
          <h2>By file type</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>File type</th>
                  <th className="num">Samples</th>
                  <th className="num">ROC-AUC</th>
                  <th className="num">Detected at 1% FPR</th>
                  <th className="num">Detected at 0.1% FPR</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(byType).map(([k, r]) => (
                  <tr key={k}>
                    <td>{k}</td>
                    <td className="num">{num(r.n)}</td>
                    <td className="num">{num(r.roc_auc, 4)}</td>
                    <td className="num">{pct(r.tpr_at_fpr_curve?.["0.01"])}</td>
                    <td className="num">{pct(r.tpr_at_fpr_curve?.["0.001"])}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {comp && (
        <section className="section">
          <h2>Compared with LightGBM on the same test files</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Detector</th>
                  <th className="num">Detected at 1% FPR</th>
                  <th className="num">Detected at 0.1% FPR</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(comp).map(([k, v]) => (
                  <tr key={k}>
                    <td>{k === "mlp" ? "Neural network" : k === "lightgbm" ? "LightGBM" : "Average of both"}</td>
                    <td className="num">
                      {pct(v["test_tpr_at_fpr_0.01"]?.value)} <span className="muted xs">{ci(v["test_tpr_at_fpr_0.01"]?.ci95, (x) => pct(x))}</span>
                    </td>
                    <td className="num">
                      {pct(v["test_tpr_at_fpr_0.001"]?.value)} <span className="muted xs">{ci(v["test_tpr_at_fpr_0.001"]?.ci95, (x) => pct(x))}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}
