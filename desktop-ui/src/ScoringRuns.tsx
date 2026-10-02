import { useEffect, useRef, useState } from "react";
import { ChevronRight, ClipboardCheck } from "lucide-react";
import type { CatalogItem, StudioApi, StudioJob, StudioSnapshot } from "./api";
import { formatTime, StatusBadge } from "./components";
import { chronologicalJobs, jobSubmittedAt } from "./jobOrder";
import { generationIsCurrent, jobState, OperationStatus } from "./ScenarioStates";
import { ScorecardPanel } from "./ScorecardPanel";
import { latestRunState } from "./workspaceSummaries";

function evaluationResult(job?: StudioJob): string {
  if (!job) return "Not evaluated";
  if (job.status !== "completed") return `Evaluation ${job.status}`;
  const score = job.scorecard;
  if (!score || score.error) return "Score unavailable";
  return `${score.overall_score?.toFixed(0) ?? "N/A"}/100 · ${score.acceptance_passed === true ? "Passed" : score.acceptance_passed === false ? "Failed" : "Indeterminate"}`;
}

/** One generation owns its evaluation history and directly expandable scorecard. */
function ScoringRun({ generation, evaluations, item, snapshot, api, focusId, focusVersion, latest, onEvaluate, evaluating, onNavigateJob }: {
  generation: StudioJob; evaluations: StudioJob[]; item: CatalogItem; snapshot: StudioSnapshot;
  api: StudioApi; focusId: string | null; focusVersion: number; latest: boolean; evaluating: boolean;
  onEvaluate: () => void; onNavigateJob: (job: StudioJob) => void;
}) {
  const newest = evaluations[evaluations.length - 1];
  const [expanded, setExpanded] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const row = useRef<HTMLElement>(null);
  const toggle = useRef<HTMLButtonElement>(null);
  const selected = evaluations.find((job) => job.id === selectedId) || newest;
  const active = [...evaluations].reverse().find((job) => ["running", "queued", "paused"].includes(job.status));
  const focused = Boolean(focusId && (focusId === generation.id || evaluations.some((job) => job.id === focusId)));
  const current = generationIsCurrent(generation, item, snapshot);
  const bodyId = `score-body-${generation.id}`;
  const previous = evaluations.filter((job) => job.id !== newest?.id).reverse();
  useEffect(() => {
    if (!focused) return;
    setExpanded(true);
    setSelectedId(focusId === generation.id ? null : focusId);
    const frame = requestAnimationFrame(() => {
      toggle.current?.focus({ preventScroll: true });
      row.current?.scrollIntoView?.({ block: "nearest" });
    });
    return () => cancelAnimationFrame(frame);
  }, [focusId, generation.id, focused, focusVersion]);
  return <section ref={row} id={`score-run-${generation.id}`} className="job-row score-run" aria-label={`Scoring run ${generation.id}`}>
    <header className="score-run-header">
      <button ref={toggle} className="score-run-toggle" aria-label={`Run #${generation.id.slice(0, 8)}`} aria-expanded={expanded} aria-controls={bodyId} onClick={() => setExpanded(!expanded)}>
        <ChevronRight size={16} className={`disclosure-chevron ${expanded ? "expanded" : ""}`} />
        <span className="score-run-identity"><strong>Run #{generation.id.slice(0, 8)}{latest && <small>Latest</small>}</strong><small>{jobSubmittedAt(generation) ? formatTime(jobSubmittedAt(generation)) : "Time unknown"} · {current ? "Current revision" : "Older revision or dependencies"}</small></span>
        <span className="score-run-result"><OperationStatus status={latestRunState("Evaluation", newest, current)} focusable={false} /><strong>{evaluationResult(newest)}</strong>{newest?.scorecard?.total_records != null && <small>{newest.scorecard.total_records.toLocaleString()} records</small>}</span>
      </button>
      <button className="button-quiet score-run-evaluate" disabled={evaluating || Boolean(active) || generation.status !== "completed"} onClick={onEvaluate} title={generation.status !== "completed" ? `Generation is ${generation.status}; only completed runs can be evaluated` : active ? "An evaluation for this run is already queued, running, or paused" : "Evaluate this run's captured data"}><ClipboardCheck size={15} />{evaluating ? "Queuing…" : active ? active.status === "paused" ? "Evaluation paused" : "Evaluation in progress" : newest ? "Re-evaluate" : "Evaluate"}</button>
    </header>
    <div id={bodyId} hidden={!expanded} className="score-run-details">{expanded && <>
      {!current && <p className="run-revision-note">This score describes the run's captured inputs; the scenario or its dependencies have changed.</p>}
      {generation.status !== "completed" && <p className="muted small"><StatusBadge status={generation.status} /> Complete this generation before scoring its data.</p>}
      {selected && <div className="score-run-report-heading"><span>Evaluation #{selected.id.slice(0, 8)} · {jobSubmittedAt(selected) ? formatTime(jobSubmittedAt(selected)) : "Time unknown"}</span>{selected.id !== newest?.id && <button className="button-quiet" onClick={() => setSelectedId(null)}>Show latest evaluation</button>}</div>}
      {selected?.status === "completed" && selected.scorecard && !selected.scorecard.error ? <ScorecardPanel key={selected.id} jobId={selected.id} api={api} /> : <p className="muted small">{selected ? selected.scorecard?.error || selected.status_message || evaluationResult(selected) : "No evaluation yet. Use Evaluate on this run to create its scorecard."}</p>}
      {previous.length > 0 && <details className="score-run-history"><summary>Earlier evaluations · {previous.length}</summary><ul>{previous.map((job) => <li key={job.id}><button className="button-quiet" onClick={() => setSelectedId(job.id)} aria-label={`View evaluation #${job.id.slice(0, 8)}`}><span>#{job.id.slice(0, 8)} · {jobSubmittedAt(job) ? formatTime(jobSubmittedAt(job)) : "Time unknown"}</span><OperationStatus status={jobState("Evaluation", job, false)} focusable={false} /><strong>{evaluationResult(job)}</strong></button></li>)}</ul></details>}
      <button className="job-source-link" onClick={() => onNavigateJob(generation)}>Jump to generation #{generation.id.slice(0, 8)}</button>
    </>}</div>
  </section>;
}

export function ScoringRuns({ jobs, item, snapshot, api, focusJobId, focusVersion = 0, onNavigateJob, onChanged, onError }: {
  jobs: StudioJob[]; item: CatalogItem; snapshot: StudioSnapshot; api: StudioApi; focusJobId: string | null; focusVersion?: number;
  onNavigateJob: (job: StudioJob) => void; onChanged: () => Promise<void>; onError: (message: string) => void;
}) {
  const [evaluating, setEvaluating] = useState<string[]>([]);
  const pending = useRef(new Set<string>());
  const generations = chronologicalJobs(jobs.filter((job) => job.kind === "generation"));
  const evaluations = chronologicalJobs(jobs.filter((job) => job.kind === "evaluation"));
  async function evaluate(generation: StudioJob) {
    if (generation.status !== "completed" || pending.current.has(generation.id) || evaluations.some((job) => job.generation_id === generation.id && ["running", "queued", "paused"].includes(job.status))) return;
    pending.current.add(generation.id);
    setEvaluating([...pending.current]);
    try { await api.request("/v1/jobs/evaluations", "POST", { generation_id: generation.id }); await onChanged(); }
    catch (error) { onError(String(error)); }
    finally { pending.current.delete(generation.id); setEvaluating([...pending.current]); }
  }
  return <div className="job-list scoring-runs">{generations.length ? generations.map((generation, index) => <ScoringRun key={generation.id} generation={generation} evaluations={evaluations.filter((job) => job.generation_id === generation.id)} latest={index === generations.length - 1} item={item} snapshot={snapshot} api={api} evaluating={evaluating.includes(generation.id)} onEvaluate={() => void evaluate(generation)} focusId={focusJobId} focusVersion={focusVersion} onNavigateJob={onNavigateJob} />) : <p className="muted">No runs yet. Generate this scenario to create data for scoring.</p>}</div>;
}
