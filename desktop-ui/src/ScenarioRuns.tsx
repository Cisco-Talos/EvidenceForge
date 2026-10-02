import { useEffect, useRef, useState } from "react";
import { ClipboardCheck, TriangleAlert } from "lucide-react";
import type { CatalogItem, ImportedBundle, StudioApi, StudioJob, StudioSnapshot } from "./api";
import { ImportedBundleRow } from "./BundleLibrary";
import { formatTime, JobCard } from "./components";
import { generationInputs, OperationStatus } from "./ScenarioStates";
import { ScorecardPanel } from "./ScorecardPanel";
import { latestJob, latestRunState, orderedBundles, scoringSummary } from "./workspaceSummaries";
import { jobSubmittedAt } from "./jobOrder";

/** A run owns its generated files and its latest saved evaluation. */
export function ScenarioRuns({ jobs, imports, sizes, item, snapshot, api, focusJobId, focusVersion, onChanged, onError }: {
  jobs: StudioJob[]; imports: ImportedBundle[]; sizes: Record<string, number | null>;
  item: CatalogItem; snapshot: StudioSnapshot; api: StudioApi; focusJobId: string | null; focusVersion: number;
  onChanged: () => Promise<void>; onError: (message: string) => void;
}) {
  const [evaluating, setEvaluating] = useState<string[]>([]);
  const [highlighted, setHighlighted] = useState<string | null>(null);
  const pending = useRef(new Set<string>());
  const generations = jobs.filter((job) => job.kind === "generation");
  const evaluations = jobs.filter((job) => job.kind === "evaluation");
  const newestRun = latestJob(generations);
  const focusedRun = generations.find((job) => job.id === focusJobId)?.id
    || evaluations.find((job) => job.id === focusJobId)?.generation_id;
  useEffect(() => {
    if (!focusedRun) return;
    const frame = requestAnimationFrame(() => {
      const row = document.getElementById(`workspace-run-${focusedRun}`);
      if (!(row instanceof HTMLDetailsElement)) return;
      row.open = true;
      row.querySelector("summary")?.focus({ preventScroll: true });
      row.scrollIntoView?.({ block: "nearest" });
      setHighlighted(focusedRun);
    });
    const timer = setTimeout(() => setHighlighted(null), 3000);
    return () => { cancelAnimationFrame(frame); clearTimeout(timer); };
  }, [focusedRun, focusJobId, focusVersion]);

  async function evaluate(generation: StudioJob) {
    if (generation.status !== "completed" || pending.current.has(generation.id)
      || evaluations.some((job) => job.generation_id === generation.id && ["running", "queued", "paused"].includes(job.status))) return;
    pending.current.add(generation.id);
    setEvaluating([...pending.current]);
    try { await api.request("/v1/jobs/evaluations", "POST", { generation_id: generation.id }); await onChanged(); }
    catch (error) { onError(String(error)); }
    finally { pending.current.delete(generation.id); setEvaluating([...pending.current]); }
  }

  return <div className="job-list scenario-runs">{orderedBundles(generations, imports).map((entry) => {
    if (entry.kind === "import") return <ImportedBundleRow key={entry.id} bundle={entry.bundle} api={api} onError={onError} onChanged={onChanged} />;
    const generation = entry.job;
    const linked = evaluations.filter((job) => job.generation_id === generation.id);
    const newest = latestJob(linked);
    const saved = latestJob(linked.filter((job) => job.status === "completed" && job.scorecard && !job.scorecard.error));
    const active = linked.find((job) => ["running", "queued", "paused"].includes(job.status));
    const inputs = generationInputs(generation, item, snapshot);
    const current = inputs.state === "current";
    const outcome = scoringSummary(generation, newest, item, snapshot);
    const queuing = evaluating.includes(generation.id);
    return <JobCard key={entry.id} idPrefix="workspace-run" job={generation} name={item.name} grouped latest={generation.id === newestRun?.id} sizeBytes={sizes[entry.id]} highlighted={highlighted === generation.id} api={api} onError={onError} onChanged={onChanged}
      summaryExtra={<span className="run-score-summary"><span><OperationStatus status={latestRunState("Evaluation", newest, current)} focusable={false} /><strong>{outcome.headline}</strong></span>{!current && <small className="summary-inputs" title={inputs.detail}><TriangleAlert size={12} aria-hidden="true" />{inputs.label}</small>}</span>}
      evaluateAction={<button className="button-quiet" disabled={queuing || Boolean(active) || generation.status !== "completed"} onClick={() => void evaluate(generation)} title={generation.status !== "completed" ? `Generation is ${generation.status}; only completed runs can be evaluated` : active ? "An evaluation for this run is already queued, running, or paused" : "Evaluate this run's captured data; a completed report replaces the previous scores"}><ClipboardCheck size={16} />{queuing ? "Queuing…" : active ? active.status === "paused" ? "Evaluation paused" : "Evaluation in progress" : saved ? "Re-evaluate" : "Evaluate"}</button>}
      detailsExtra={<div className="run-score-details">
        {!current && <p className="run-revision-note">{inputs.detail}</p>}
        {newest && newest.id !== saved?.id && <p className="muted small" role="status">{newest.scorecard?.error || newest.status_message || outcome.headline}{saved ? " · Previous saved score remains available until a new report completes." : ""}</p>}
        {saved ? <><p className="run-evaluation-date muted small">Latest saved evaluation · {jobSubmittedAt(saved) ? formatTime(jobSubmittedAt(saved)) : "Time unknown"}</p><ScorecardPanel key={saved.id} jobId={saved.id} api={api} /></> : !newest && <p className="muted small">{generation.status === "completed" ? "No evaluation yet. Use Evaluate to score this bundle." : "Complete this generation before scoring its data."}</p>}
      </div>} />;
  })}</div>;
}
