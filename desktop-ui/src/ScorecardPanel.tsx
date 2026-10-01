import { useEffect, useState } from "react";
import type { ScorecardDetail, StudioApi } from "./api";

function score(value: number | null): string {
  return value == null ? "N/A" : `${value.toFixed(0)}/100`;
}

export function ScorecardPanel({ jobId, api }: { jobId: string; api: StudioApi }) {
  const [report, setReport] = useState<ScorecardDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void api.request<ScorecardDetail>(`/v1/jobs/${jobId}/scorecard`)
      .then((value) => { if (!cancelled) setReport(value); })
      .catch((reason) => { if (!cancelled) setError(String(reason)); });
    return () => { cancelled = true; };
  }, [api, jobId]);

  if (error) return <div className="scorecard-detail error-text" role="alert">{error}</div>;
  if (!report) return <div className="scorecard-detail muted" role="status">Loading saved scorecard…</div>;

  return <section className="scorecard-detail" aria-label="Saved scorecard">
    <div className="scorecard-detail-heading"><div><span className="eyebrow">SAVED EVALUATION</span><h3>{report.scenario_name}</h3><small>Evaluated {new Date(report.evaluated_at).toLocaleString()} · {report.total_records.toLocaleString()} records</small></div><div className="scorecard-detail-total"><strong>{score(report.overall_score)}</strong><span className={report.acceptance_passed === true ? "score-pass" : report.acceptance_passed === false ? "score-fail" : ""}>{report.acceptance_passed === true ? "PASS" : report.acceptance_passed === false ? "FAIL" : "INDETERMINATE"}</span></div></div>
    {report.flags.length > 0 && <div className="scorecard-flags"><strong>Flags</strong><ul>{report.flags.map((flag, index) => <li key={`${flag}-${index}`}>{flag}</li>)}</ul></div>}
    <div className="scorecard-pillars">{report.pillars.map((pillar, index) => <div className="scorecard-pillar" key={`${pillar.name}-${index}`}><div className="scorecard-pillar-heading"><strong>{pillar.name}</strong><span>{score(pillar.score)}</span></div>{pillar.sub_scores.length > 0 && <ul>{pillar.sub_scores.map((sub, subIndex) => <li key={`${sub.name}-${subIndex}`}><span>{sub.name}{sub.skipped ? " · Skipped" : ""}</span><strong>{score(sub.score)}</strong>{sub.details && <small>{sub.details}</small>}</li>)}</ul>}</div>)}</div>
    {report.acceptance_criteria.length > 0 && <div className="scorecard-criteria"><h4>Acceptance checks</h4><ul>{report.acceptance_criteria.map((criterion, index) => <li key={`${criterion.name}-${index}`}><span className={criterion.passed === true ? "score-pass" : criterion.passed === false ? "score-fail" : ""}>{criterion.passed === true ? "Pass" : criterion.passed === false ? "Fail" : "N/A"}</span><strong>{criterion.name}</strong><small>{criterion.actual == null ? "No score" : criterion.actual.toFixed(0)} / {criterion.threshold.toFixed(0)} threshold · {criterion.level}</small></li>)}</ul></div>}
    {Object.keys(report.source_counts).length > 0 && <details className="scorecard-sources"><summary>Records by source</summary><ul>{Object.entries(report.source_counts).sort((a, b) => b[1] - a[1]).map(([source, count]) => <li key={source}><span>{source}</span><strong>{count.toLocaleString()}</strong></li>)}</ul></details>}
  </section>;
}
