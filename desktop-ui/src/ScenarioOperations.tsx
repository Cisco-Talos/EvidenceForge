import { useState } from "react";
import { ClipboardCheck, Play } from "lucide-react";
import type { CatalogItem, StudioApi, StudioJob, StudioSnapshot } from "./api";
import { formatTime } from "./components";
import { chronologicalJobs } from "./jobOrder";
import { ResourceForecastPanel } from "./ResourceForecastPanel";
import { JobSections } from "./JobSections";

export function ScenarioOperations({ mode, item, jobs, api, snapshot, onGenerate, generating, dependenciesReady = true, onError, onChanged, focusJobId, onNavigateJob, embedded = false }: {
  snapshot: StudioSnapshot; mode: "generation" | "scoring"; item: CatalogItem; jobs: StudioJob[]; api: StudioApi;
  onGenerate: () => Promise<void>; generating: boolean; dependenciesReady?: boolean; onError: (error: string) => void;
  onChanged: () => Promise<void>; focusJobId: string | null; onNavigateJob: (job: StudioJob) => void; embedded?: boolean;
}) {
  const [selectedRun, setSelectedRun] = useState("");
  const [evaluating, setEvaluating] = useState(false);
  const completed = chronologicalJobs(jobs.filter((job) => job.kind === "generation" && job.status === "completed")).reverse();
  const selected = completed.find((job) => job.id === selectedRun) || completed[0];
  const scoringActive = selected && jobs.some((job) => job.kind === "evaluation" && job.generation_id === selected.id && ["queued", "running"].includes(job.status));
  async function evaluate() {
    if (!selected || evaluating || scoringActive) return;
    setEvaluating(true);
    try {
      await api.request("/v1/jobs/evaluations", "POST", { generation_id: selected.id });
      await onChanged();
    } catch (error) { onError(String(error)); }
    finally { setEvaluating(false); }
  }
  return <div className={embedded ? "workspace-operation-details" : "workspace-content"}>
    {mode === "generation" && <ResourceForecastPanel item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} />}
    {(!embedded || mode === "scoring") && <section className="run-setup surface">
      <div><h2>{mode === "generation" ? "Generate this scenario" : "Score a generated run"}</h2><p>{mode === "generation" ? "Each generation creates a separate bundle in the output folder configured in Settings." : "Evaluate the logs from a completed run and keep its scorecard with this scenario."}</p></div>
      {mode === "generation" ? <div className="run-controls"><button className="button-primary" onClick={() => void onGenerate()} disabled={generating || !dependenciesReady} title={!dependenciesReady ? "Resolve dependency errors first" : undefined}><Play size={16} /> {generating ? "Queuing…" : "Generate"}</button></div> : completed.length ? <><label className="run-setup-label" htmlFor="scoring-run">Generated run</label><div className="run-controls"><select id="scoring-run" aria-label="Generated run to evaluate" value={selected?.id || ""} onChange={(event) => setSelectedRun(event.target.value)}>{completed.map((job) => <option key={job.id} value={job.id}>{formatTime(job.started_at || job.created_at || 0)} · Run #{job.id.slice(0, 8)}</option>)}</select><button className="button-primary" onClick={() => void evaluate()} disabled={evaluating || !!scoringActive}><ClipboardCheck size={16} /> {evaluating ? "Queuing…" : scoringActive ? "Evaluation in progress" : "Evaluate"}</button></div>{selected?.source_sha256 && selected.source_sha256 !== item.source_sha256 && <p className="run-revision-note">This run uses an earlier scenario revision.</p>}</> : <p className="muted">Complete a generation to enable evaluation.</p>}
    </section>}
    {!embedded && <div className="section-heading"><div><h2>{mode === "generation" ? "Generation history" : "Scores and evaluations"}</h2><p>{mode === "generation" ? "Every run keeps its own output and progress, in start order." : "Open an evaluation row to see its saved scorecard and source generation."}</p></div></div>}
    <JobSections flat={embedded} jobs={jobs} kinds={[mode === "generation" ? "generation" : "evaluation"]} nameFor={() => item.name} api={api} onError={onError} onChanged={onChanged} focusJobId={focusJobId} onNavigateJob={onNavigateJob} />
  </div>;
}
