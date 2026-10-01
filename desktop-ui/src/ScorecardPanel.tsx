import { useEffect, useState } from "react";
import { CheckCircle2, ChevronDown, CircleMinus, Download, FileCode2, TriangleAlert, XCircle } from "lucide-react";
import { Tooltip } from "radix-ui";
import { isTauri } from "@tauri-apps/api/core";
import type { ScorecardDetail, StudioApi, TextPreview } from "./api";
import { ChatMarkdown } from "./ChatMarkdown";
import { CopyPathButton } from "./CopyPathButton";

function score(value: number | null): string {
  return value == null ? "N/A" : `${value.toFixed(0)}/100`;
}

type Measure = ScorecardDetail["pillars"][number]["sub_scores"][number];

function ScoreResult({ sub }: { sub: Measure }) {
  const rating = sub.rating || "unrated";
  const Icon = rating === "passed" ? CheckCircle2 : rating === "failed" ? XCircle : rating === "marginal" ? TriangleAlert : CircleMinus;
  const label = rating === "marginal" ? "Marginal: minimum passed, aspirational target missed" : rating === "unrated" ? sub.skipped ? "Skipped" : "Unrated" : rating === "passed" ? "Passed" : "Failed";
  const detail = `${label}. ${sub.rating_detail || "No recorded verdict or applicable reference threshold."}`;
  return <span className="subscore-result"><strong>{score(sub.score)}</strong><Tooltip.Root><Tooltip.Trigger asChild><span className={`subscore-icon subscore-${rating}`} tabIndex={0} aria-label={`${sub.name}: ${detail}`}><Icon size={15} /></span></Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="state-tooltip" sideOffset={6}>{detail}<Tooltip.Arrow className="state-tooltip-arrow" /></Tooltip.Content></Tooltip.Portal></Tooltip.Root></span>;
}

function pillarResult(pillar: ScorecardDetail["pillars"][number]): Measure {
  const measures = pillar.sub_scores.filter((sub) => !sub.skipped);
  const failed = measures.filter((sub) => sub.rating === "failed").length;
  const marginal = measures.filter((sub) => sub.rating === "marginal").length;
  const unrated = measures.filter((sub) => !sub.rating || sub.rating === "unrated").length;
  const rating = failed ? "failed" : marginal ? "marginal" : !measures.length || unrated ? "unrated" : "passed";
  const detail = !measures.length ? "No applicable measures." : `${failed} failed, ${marginal} marginal, ${unrated} unrated out of ${measures.length} applicable measures. Status summarizes the measures below; it does not replace saved acceptance. Expand for each measure’s threshold and source.`;
  return { name: pillar.name, score: pillar.score, skipped: !measures.length, details: "", rating, rating_detail: detail };
}

export function ScorecardPanel({ jobId, api, compact = false }: { jobId: string; api: StudioApi; compact?: boolean }) {
  const [report, setReport] = useState<ScorecardDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [raw, setRaw] = useState<TextPreview | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [rawError, setRawError] = useState<string | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setReport(null); setError(null); setRaw(null); setShowRaw(false); setRawError(null); setSavedPath(null);
    void api.request<ScorecardDetail>(`/v1/jobs/${jobId}/scorecard`)
      .then((value) => { if (!cancelled) setReport(value); })
      .catch((reason) => { if (!cancelled) setError(String(reason)); });
    return () => { cancelled = true; };
  }, [api, jobId]);

  useEffect(() => {
    if (!showRaw || raw) return;
    let cancelled = false;
    void api.readTextPreview(`/v1/jobs/${jobId}/report`, 64 * 1024)
      .then((value) => { if (!cancelled) setRaw(value); })
      .catch((reason) => { if (!cancelled) setRawError(String(reason)); });
    return () => { cancelled = true; };
  }, [api, jobId, showRaw, raw]);

  async function exportReport() {
    setExporting(true); setRawError(null);
    try {
      const result = await api.download(`/v1/jobs/${jobId}/report`, `evaluation-${jobId.slice(0, 8)}.json`);
      if (result.status === "saved") setSavedPath(result.path);
    } catch (reason) { setRawError(String(reason)); }
    finally { setExporting(false); }
  }

  if (error) return <div className="scorecard-detail error-text" role="alert">{error}</div>;
  if (!report) return <div className="scorecard-detail muted" role="status">Loading saved scorecard…</div>;

  const failed = report.acceptance_criteria.filter((criterion) => criterion.level === "hard" && criterion.applicable !== false && criterion.passed === false);
  const verdict = report.acceptance_passed === true ? "Acceptance passed" : report.acceptance_passed === false ? "Acceptance failed" : "Acceptance indeterminate";
  const verdictClass = report.acceptance_passed === true ? "score-pass" : report.acceptance_passed === false ? "score-fail" : "score-indeterminate";

  return <Tooltip.Provider><section className={`scorecard-detail ${compact ? "scorecard-compact" : ""}`} aria-label="Saved scorecard">
    <div className="scorecard-detail-heading">{!compact && <div><span className="eyebrow">SAVED EVALUATION</span><h3>{report.scenario_name}</h3><small>Evaluated {new Date(report.evaluated_at).toLocaleString()} · {report.total_records.toLocaleString()} records</small></div>}<div className="scorecard-detail-total"><strong>{score(report.overall_score)}</strong><span className={verdictClass}>{verdict}</span></div></div>
    <p className={`scorecard-verdict ${verdictClass}`}>{report.acceptance_passed === false ? `${failed.length || "One or more"} required check${failed.length === 1 ? "" : "s"} failed. The overall score does not override required checks.` : report.acceptance_passed === true ? "All applicable required checks passed." : "There is not enough evaluated evidence to determine acceptance."}</p>
    {compact && <small className="muted">{report.total_records.toLocaleString()} records</small>}
    <div className="scorecard-pillars">{report.pillars.map((pillar, index) => <details className="scorecard-pillar" key={`${jobId}-${pillar.name}-${index}`}>
      <summary className="scorecard-pillar-heading"><strong>{pillar.name}</strong><ScoreResult sub={pillarResult(pillar)} /><ChevronDown className="pillar-chevron" size={14} /></summary>
      {pillar.sub_scores.length ? <ul>{pillar.sub_scores.map((sub, subIndex) => <li key={`${sub.name}-${subIndex}`}><span>{sub.name}{sub.skipped ? " · Skipped" : ""}</span><ScoreResult sub={sub} />{sub.details && <small>{sub.details}</small>}</li>)}</ul> : <p className="muted small">No subscores recorded.</p>}
    </details>)}</div>
    {!compact && <>
      {report.acceptance_criteria.length > 0 && <details className="scorecard-criteria" key={`criteria-${jobId}`}><summary>Acceptance checks <span className={failed.length ? "score-fail" : ""}>{failed.length ? `${failed.length} required checks failed` : `${report.acceptance_criteria.length} checks`}</span><ChevronDown size={14} /></summary><ul>{report.acceptance_criteria.map((criterion, index) => <li key={`${criterion.name}-${index}`}><span className={criterion.passed === true ? "score-pass" : criterion.passed === false && criterion.applicable !== false ? "score-fail" : ""}>{criterion.applicable === false ? "N/A" : criterion.passed === true ? "Pass" : criterion.passed === false ? "Fail" : "N/A"}</span><strong>{criterion.name}</strong><small>{criterion.actual == null ? "No score" : criterion.actual.toFixed(0)} / {criterion.threshold.toFixed(0)} threshold · {criterion.level === "hard" ? "Required" : "Target"}</small></li>)}</ul></details>}
      {report.flags.length > 0 && <details className="scorecard-flags"><summary>Flags <span>{report.flags.length}</span></summary><ul>{report.flags.map((flag, index) => <li key={`${flag}-${index}`}>{flag}</li>)}</ul></details>}
      {Object.keys(report.source_counts).length > 0 && <details className="scorecard-sources"><summary>Records by source</summary><ul>{Object.entries(report.source_counts).sort((a, b) => b[1] - a[1]).map(([source, count]) => <li key={source}><span>{source}</span><strong>{count.toLocaleString()}</strong></li>)}</ul></details>}
      <div className="scorecard-report-actions"><button className="button-quiet" aria-expanded={showRaw} onClick={() => setShowRaw(!showRaw)}><FileCode2 size={14} /> {showRaw ? "Hide raw report" : "View raw report"}</button><button className="button-quiet" disabled={exporting} onClick={() => void exportReport()}><Download size={14} /> {exporting ? "Saving…" : isTauri() ? "Export report JSON" : "Download report JSON"}</button></div>
      {rawError && <p className="error-text" role="alert">{rawError}</p>}
      {savedPath && <div className="path-with-copy muted small"><span className="path-value">Saved to {savedPath}</span><CopyPathButton path={savedPath} label="Copy saved report path" onError={setRawError} /></div>}
      {showRaw && <div className="scorecard-raw" aria-label="Raw evaluation report">{!raw && !rawError ? <p className="muted" role="status">Loading report…</p> : raw?.binary ? <p className="error-text">This report cannot be previewed as text.</p> : raw && <><ChatMarkdown text={`\`\`\`json\n${raw.text}\n\`\`\``} />{raw.truncated && <p className="muted small">Preview limited to 64 KB. Export the JSON for the full report.</p>}</>}</div>}
    </>}
  </section></Tooltip.Provider>;
}
