import { useEffect, useRef, useState } from "react";
import type { StudioApi, StudioJob } from "./api";
import { JobCard } from "./components";
import { chronologicalJobs } from "./jobOrder";

export function JobSections({ jobs, nameFor, api, onError, onChanged }: {
  jobs: StudioJob[]; nameFor: (job: StudioJob) => string | undefined; api: StudioApi;
  onError: (message: string) => void; onChanged: () => Promise<void>;
}) {
  const [openKinds, setOpenKinds] = useState<Record<string, boolean>>({});
  const [highlightedJobId, setHighlightedJobId] = useState<string | null>(null);
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
  }, []);

  function showSource(generationId: string) {
    const source = document.getElementById(`job-${generationId}`);
    if (!(source instanceof HTMLDetailsElement)) {
      onError("The source generation is no longer in this run history.");
      return;
    }
    const group = source.closest(".job-group");
    if (group instanceof HTMLDetailsElement) {
      group.open = true;
      setOpenKinds((current) => ({ ...current, generation: true }));
    }
    source.open = true;
    setHighlightedJobId(generationId);
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
    highlightTimer.current = setTimeout(() => setHighlightedJobId(null), 3000);
    source.querySelector("summary")?.focus({ preventScroll: true });
    source.scrollIntoView?.({ block: "center", behavior: "auto" });
  }

  return <div className="job-sections">{(["generation", "evaluation"] as const).map((kind) => {
    const entries = chronologicalJobs(jobs.filter((job) => job.kind === kind));
    const active = entries.filter((job) => ["running", "queued", "paused"].includes(job.status)).length;
    return <details className="job-group" key={kind} open={openKinds[kind] ?? true} onToggle={(event) => { const open = event.currentTarget.open; setOpenKinds((current) => ({ ...current, [kind]: open })); }}>
      <summary><strong>{kind === "generation" ? "Generations" : "Evaluations"}</strong><span>{entries.length}</span>{active > 0 && <small>{active} active or queued</small>}</summary>
      <div className="job-list">{entries.length ? entries.map((job) => <JobCard key={job.id} job={job} name={nameFor(job)} highlighted={job.id === highlightedJobId} onShowSource={showSource} api={api} onError={onError} onChanged={onChanged} />) : <p className="muted job-group-empty">No {kind === "generation" ? "generations" : "evaluations"} yet.</p>}</div>
    </details>;
  })}</div>;
}
