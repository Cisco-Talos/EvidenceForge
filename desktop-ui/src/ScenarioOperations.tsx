import { Play } from "lucide-react";
import type { CatalogItem, StudioApi, StudioJob, StudioSnapshot } from "./api";
import { ResourceForecastPanel } from "./ResourceForecastPanel";
import { JobSections } from "./JobSections";
import { ScoringRuns } from "./ScoringRuns";

export function ScenarioOperations({ mode, item, jobs, api, snapshot, onGenerate, generating, dependenciesReady = true, onError, onChanged, focusJobId, onNavigateJob, focusVersion = 0, embedded = false }: {
  snapshot: StudioSnapshot; mode: "generation" | "scoring"; item: CatalogItem; jobs: StudioJob[]; api: StudioApi;
  onGenerate: () => Promise<void>; generating: boolean; dependenciesReady?: boolean; onError: (error: string) => void;
  onChanged: () => Promise<void>; focusJobId: string | null; onNavigateJob: (job: StudioJob) => void; focusVersion?: number; embedded?: boolean;
}) {
  if (mode === "scoring") return <ScoringRuns jobs={jobs} item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} focusJobId={focusJobId} focusVersion={focusVersion} onNavigateJob={onNavigateJob} />;
  return <div className={embedded ? "workspace-operation-details" : "workspace-content"}>
    {mode === "generation" && <ResourceForecastPanel item={item} snapshot={snapshot} api={api} onError={onError} onChanged={onChanged} />}
    {!embedded && <section className="run-setup surface"><div><h2>Generate this scenario</h2><p>Each generation creates a separate bundle in the output folder configured in Settings.</p></div><div className="run-controls"><button className="button-primary" onClick={() => void onGenerate()} disabled={generating || !dependenciesReady} title={!dependenciesReady ? "Resolve dependency errors first" : undefined}><Play size={16} /> {generating ? "Queuing…" : "Generate"}</button></div></section>}
    {!embedded && <div className="section-heading"><div><h2>Generation history</h2><p>Every run keeps its own output and progress, in start order.</p></div></div>}
    <JobSections flat={embedded} jobs={jobs} kinds={["generation"]} nameFor={() => item.name} api={api} onError={onError} onChanged={onChanged} focusJobId={focusJobId} onNavigateJob={onNavigateJob} />
  </div>;
}
