import { useEffect, useRef, useState } from "react";
import { Trash2 } from "lucide-react";
import type { StudioApi, StudioJob } from "./api";
import { JobCard } from "./components";
import { chronologicalJobs } from "./jobOrder";

export function JobSections({ jobs, nameFor, api, onError, onChanged, focusJobId, kinds = ["generation", "evaluation"], onNavigateJob, manageHistory = false, removedJobIds = [] }: {
  jobs: StudioJob[]; nameFor: (job: StudioJob) => string | undefined; api: StudioApi;
  onError: (message: string) => void; onChanged: () => Promise<void>; focusJobId?: string | null;
  kinds?: ("generation" | "evaluation")[];
  onNavigateJob?: (job: StudioJob) => void;
  manageHistory?: boolean; removedJobIds?: string[];
}) {
  const [openKinds, setOpenKinds] = useState<Record<string, boolean>>({});
  const [highlightedJobId, setHighlightedJobId] = useState<string | null>(null);
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [removed, setRemoved] = useState<string[]>([]);
  const [clearing, setClearing] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<string[]>([]);
  const [pendingJobId, setPendingJobId] = useState<string | null>(null);
  const visibleJobs = jobs.filter((job) => !manageHistory || ["running", "queued", "paused"].includes(job.status) || revealed.includes(job.id) || (!removedJobIds.includes(job.id) && !removed.includes(job.id)));

  async function removeHistory(jobId: string) {
    try {
      await api.request(`/v1/jobs/${jobId}/history`, "DELETE");
      setRemoved((current) => [...current, jobId]);
      setRevealed((current) => current.filter((id) => id !== jobId));
      await onChanged();
    } catch (error) { onError(String(error)); }
  }

  async function clearCompleted(kind: "generation" | "evaluation") {
    setClearing(kind);
    try {
      const result = await api.request<{ job_ids: string[] }>("/v1/jobs/history/clear-completed", "POST", { kind });
      const cleared = new Set([...result.job_ids, ...jobs.filter((job) => job.kind === kind && job.status === "completed").map((job) => job.id)]);
      setRemoved((current) => [...current, ...cleared]);
      setRevealed((current) => current.filter((id) => !cleared.has(id)));
      await onChanged();
    } catch (error) { onError(String(error)); }
    finally { setClearing(null); }
  }

  useEffect(() => () => {
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
  }, []);

  useEffect(() => {
    if (focusJobId && jobs.some((job) => job.id === focusJobId)) showJob(focusJobId);
  }, [focusJobId]);

  useEffect(() => {
    if (pendingJobId && revealed.includes(pendingJobId)) {
      showJob(pendingJobId);
      setPendingJobId(null);
    }
  }, [pendingJobId, revealed]);

  function showJob(jobId: string) {
    if (manageHistory && !visibleJobs.some((job) => job.id === jobId) && jobs.some((job) => job.id === jobId)) {
      setRevealed((current) => [...current, jobId]);
      setPendingJobId(jobId);
      return;
    }
    const source = document.getElementById(`job-${jobId}`);
    if (!(source instanceof HTMLDetailsElement)) {
      const target = jobs.find((job) => job.id === jobId);
      if (target && onNavigateJob) { onNavigateJob(target); return; }
      onError("The selected job is no longer in this run history.");
      return;
    }
    const group = source.closest(".job-group");
    if (group instanceof HTMLDetailsElement) {
      group.open = true;
      const kind = jobs.find((job) => job.id === jobId)?.kind;
      if (kind) setOpenKinds((current) => ({ ...current, [kind]: true }));
    }
    source.open = true;
    setHighlightedJobId(jobId);
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
    highlightTimer.current = setTimeout(() => setHighlightedJobId(null), 3000);
    source.querySelector("summary")?.focus({ preventScroll: true });
    source.scrollIntoView?.({ block: "center", behavior: "auto" });
  }

  return <div className="job-sections">{kinds.map((kind) => {
    const entries = chronologicalJobs(visibleJobs.filter((job) => job.kind === kind));
    const active = entries.filter((job) => ["running", "queued", "paused"].includes(job.status)).length;
    return <details className="job-group" key={kind} open={openKinds[kind] ?? true} onToggle={(event) => { const open = event.currentTarget.open; setOpenKinds((current) => ({ ...current, [kind]: open })); }}>
      <summary><strong>{kind === "generation" ? "Generations" : "Evaluations"}</strong><span>{entries.length}</span>{active > 0 && <small>{active} active or queued</small>}{manageHistory && <button className="button-quiet clear-completed" aria-label={`Clear completed ${kind === "generation" ? "generations" : "evaluations"}`} title="Remove completed jobs from Job center. Bundles and scorecards are kept." disabled={clearing !== null || !entries.some((job) => job.status === "completed")} onClick={(event) => { event.preventDefault(); event.stopPropagation(); void clearCompleted(kind); }}><Trash2 size={14} /> {clearing === kind ? "Clearing…" : "Clear Completed"}</button>}</summary>
      <div className="job-list">{entries.length ? entries.map((job) => <JobCard key={job.id} job={job} name={nameFor(job)} onDeleteHistory={manageHistory ? () => removeHistory(job.id) : undefined} highlighted={job.id === highlightedJobId} focusScorecard={job.id === focusJobId && job.kind === "evaluation"} onShowSource={showJob} api={api} onError={onError} onChanged={onChanged} />) : <p className="muted job-group-empty">No {kind === "generation" ? "generations" : "evaluations"} in this list.</p>}</div>
    </details>;
  })}</div>;
}
