import { useEffect, useRef, useState } from "react";
import { ActionShortcut, ObjectMenu, RemovalConfirmation, type ObjectAction } from "./ObjectActions";
import type { StudioApi, StudioJob } from "./api";
import { formatTime, JobCard } from "./components";
import { recentJobs, jobSubmittedAt } from "./jobOrder";
import { jobStatusCounts } from "./workspaceSummaries";
import { HeaderSummary } from "./WorkspaceSection";
import { completedSuccessfully } from "./jobOutcomes";

const finishedStatuses = ["completed", "failed", "stopped", "cancelled"];

export function JobSections({ jobs, nameFor, api, onError, onChanged, focusJobId, kinds = ["generation", "evaluation"], onNavigateJob, manageHistory = false, removedJobIds = [], flat = false }: {
  jobs: StudioJob[]; nameFor: (job: StudioJob) => string | undefined; api: StudioApi;
  onError: (message: string) => void; onChanged: () => Promise<void>; focusJobId?: string | null;
  kinds?: ("generation" | "evaluation")[];
  onNavigateJob?: (job: StudioJob) => void;
  manageHistory?: boolean; removedJobIds?: string[]; flat?: boolean;
}) {
  const [openKinds, setOpenKinds] = useState<Record<string, boolean>>({});
  const [highlightedJobId, setHighlightedJobId] = useState<string | null>(null);
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [removed, setRemoved] = useState<string[]>([]);
  const [confirmClear, setConfirmClear] = useState<{ kind: "generation" | "evaluation"; mode: "completed" | "finished" } | null>(null);
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
      return true;
    } catch (error) { onError(String(error)); return false; }
  }

  async function clearHistory(kind: "generation" | "evaluation", mode: "completed" | "finished") {
    setClearing(kind);
    try {
      const result = await api.request<{ job_ids: string[] }>(`/v1/jobs/history/clear-${mode}`, "POST", { kind });
      // A source link can reveal an already-cleared job. Hide it again only if
      // it still meets this action's criteria; fresh removals come from the API.
      const previouslyCleared = visibleJobs.filter((job) => job.kind === kind && removedJobIds.includes(job.id)
        && (mode === "finished" ? finishedStatuses.includes(job.status) : completedSuccessfully(job)));
      const cleared = new Set([...result.job_ids, ...previouslyCleared.map((job) => job.id)]);
      setRemoved((current) => [...current, ...cleared]);
      setRevealed((current) => current.filter((id) => !cleared.has(id)));
      await onChanged();
      setConfirmClear(null);
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

  return <><div className="job-sections">{kinds.map((kind) => {
    const entries = recentJobs(visibleJobs.filter((job) => job.kind === kind));
    const latest = entries[0];
    const kindLabel = kind === "generation" ? "generations" : "evaluations";
    const canClearCompleted = entries.some(completedSuccessfully);
    const canClearFinished = entries.some((job) => finishedStatuses.includes(job.status));
    const historyActions: ObjectAction[] = [
      { id: "completed", label: "Clear completed", group: "remove", disabled: clearing !== null || !canClearCompleted, reason: clearing !== null ? "History cleanup is in progress" : "No successful completed jobs to clear", description: "Keep bundles and scorecards; clear successful jobs", run: () => setConfirmClear({ kind, mode: "completed" }) },
      { id: "finished", label: "Clear finished", group: "remove", disabled: clearing !== null || !canClearFinished, reason: clearing !== null ? "History cleanup is in progress" : "No finished jobs to clear", description: "Keep bundles and scorecards; clear all finished jobs", run: () => setConfirmClear({ kind, mode: "finished" }) },
    ];
    if (flat) return <div key={kind} className="job-list">{entries.map((job) => <JobCard key={job.id} job={job} name={nameFor(job)} highlighted={job.id === highlightedJobId} focusScorecard={job.id === focusJobId && job.kind === "evaluation"} onShowSource={showJob} api={api} onError={onError} onChanged={onChanged} />)}</div>;
    return <details className="job-group" key={kind} open={openKinds[kind] ?? true} onToggle={(event) => { const open = event.currentTarget.open; setOpenKinds((current) => ({ ...current, [kind]: open })); }}>
      <summary><strong>{kind === "generation" ? "Generations" : "Evaluations"}</strong><span>{entries.length}</span><small className="group-summary"><HeaderSummary summary={{ headline: jobStatusCounts(entries) || "No jobs", detail: latest ? `Latest: ${nameFor(latest) || "Run"} #${latest.id.slice(0, 8)}${jobSubmittedAt(latest) ? ` · ${formatTime(jobSubmittedAt(latest))}` : ""}` : "" }} /></small>{manageHistory && <div className="job-history-actions" onClick={(event) => { event.preventDefault(); event.stopPropagation(); }} onKeyDown={(event) => event.stopPropagation()}>
        <ActionShortcut action={historyActions[0]} className="clear-completed" ariaLabel={`Clear completed ${kindLabel}`} /><ObjectMenu label={`History actions for ${kindLabel}`} actions={historyActions} />
      </div>}</summary>
      <div className="job-list">{entries.length ? entries.map((job) => <JobCard key={job.id} job={job} name={nameFor(job)} onDeleteHistory={manageHistory ? () => removeHistory(job.id) : undefined} highlighted={job.id === highlightedJobId} focusScorecard={job.id === focusJobId && job.kind === "evaluation"} onShowSource={showJob} api={api} onError={onError} onChanged={onChanged} />) : <p className="muted job-group-empty">No {kind === "generation" ? "generations" : "evaluations"} in this list.</p>}</div>
    </details>;
  })}</div>{confirmClear && <RemovalConfirmation title={`Clear ${confirmClear.mode} ${confirmClear.kind === "generation" ? "generations" : "evaluations"}?`} label={`Clear ${confirmClear.mode}`} busy={clearing !== null} onCancel={() => setConfirmClear(null)} onConfirm={() => clearHistory(confirmClear.kind, confirmClear.mode)}><p>{confirmClear.mode === "completed" ? "Successful completed jobs will be removed from Job center. Failed and unrated evaluations remain visible." : "Completed, failed, stopped and cancelled jobs will be removed from Job center. Queued, running and paused jobs remain visible."} Bundles and saved scorecards are kept.</p></RemovalConfirmation>}</>;
}
