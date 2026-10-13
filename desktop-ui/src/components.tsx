import { useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Activity, Check, ChevronDown, CircleHelp, TriangleAlert, X } from "lucide-react";
import { Dialog, Tooltip } from "radix-ui";
import { isTauri } from "@tauri-apps/api/core";
import { StudioApi, StudioJob, ValidationResult, type ExportProgress } from "./api";
import { BundleFileBrowser, type BundleFiles } from "./BundleFileBrowser";
import { ActionShortcut, ObjectMenu, RemovalConfirmation, type ObjectAction } from "./ObjectActions";
import { JobActionContext } from "./JobActionContext";
import { latestSavedEvaluation } from "./workspaceSummaries";
import { CopyPathButton, writePathToClipboard } from "./CopyPathButton";
import { ExportStatus } from "./ExportStatus";
import { BundlePropertiesDialog } from "./ArtifactProperties";
import { jobSubmittedAt } from "./jobOrder";
import { jobDisplayStatus } from "./jobOutcomes";
import { ScorecardPanel } from "./ScorecardPanel";
import { JobDiagnostics } from "./JobDiagnostics";
import { capturedVersion } from "./bundleGrouping";

export function BundleOptionsMenu({ id, onProperties, actions }: { id: string; onProperties: () => void; actions?: ObjectAction[] }) {
  return <ObjectMenu label={`Bundle options for ${id}`} actions={actions || [{ id: "properties", label: "Properties…", group: "inspect", run: onProperties }]} />;
}

export function shortPath(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length > 3 ? `…/${parts.slice(-3).join("/")}` : path;
}

export function formatTime(value: number): string {
  return new Date(value * 1000).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
  });
}

export function formatBundleSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const unit = bytes < 1024 ** 2 ? "KB" : bytes < 1024 ** 3 ? "MB" : "GB";
  const divisor = unit === "KB" ? 1024 : unit === "MB" ? 1024 ** 2 : 1024 ** 3;
  return `${(bytes / divisor).toFixed(1)} ${unit}`;
}

export function Help({ text }: { text: string }) {
  return <Tooltip.Root delayDuration={200}><Tooltip.Trigger asChild><button className="help-icon" aria-label={text} type="button"><CircleHelp size={14} /></button></Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="tooltip" sideOffset={7}>{text}</Tooltip.Content></Tooltip.Portal></Tooltip.Root>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`status status-${status.toLowerCase().replace(/ /g, "-")}`}><span className="status-dot" />{status}</span>;
}

export function JobCard({ job, name: scenarioName, grouped = false, sizeBytes, highlighted = false, focusScorecard = false, onShowSource, onDeleteHistory, api, onError, onChanged, idPrefix = "job", summaryExtra, detailsExtra, latest = false, onNavigateRow, sourceLabel }: {
  job: StudioJob; name?: string; grouped?: boolean; sizeBytes?: number | null; highlighted?: boolean; focusScorecard?: boolean;
  onShowSource?: (generationId: string) => void; api: StudioApi;
  onDeleteHistory?: () => Promise<void | boolean>;
  onError: (message: string) => void; onChanged: () => Promise<void>; idPrefix?: string;
  summaryExtra?: ReactNode; detailsExtra?: ReactNode; latest?: boolean; onNavigateRow?: () => void;
  sourceLabel?: string;
}) {
  const context = useContext(JobActionContext);
  const row = useRef<HTMLDetailsElement>(null);
  const [propertiesOpen, setPropertiesOpen] = useState(false);
  const [files, setFiles] = useState<BundleFiles | null>(null);
  const [confirmRemoval, setConfirmRemoval] = useState<"history" | "bundle" | null>(null);
  const [requestingEvaluation, setRequestingEvaluation] = useState(false);
  const [working, setWorking] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportProgress, setExportProgress] = useState<ExportProgress | null>(null);
  const [savedExport, setSavedExport] = useState<string | null>(null);
  const [showScorecard, setShowScorecard] = useState(focusScorecard);
  const [scorecardOpen, setScorecardOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [logRequested, setLogRequested] = useState(false);
  const [logRefresh, setLogRefresh] = useState(0);
  useEffect(() => { if (focusScorecard) setShowScorecard(true); }, [focusScorecard]);
  const linked = context?.jobs.filter((entry) => entry.kind === "evaluation" && entry.generation_id === job.id) || [];
  const savedEvaluation = latestSavedEvaluation(linked);
  const activeEvaluation = linked.find((entry) => ["queued", "running", "paused"].includes(entry.status));
  const evaluationActive = !!activeEvaluation;
  const removed = context?.removedIds.includes(job.id) || false;
  const generation = job.kind === "generation";
  const terminal = ["completed", "stopped", "failed", "cancelled"].includes(job.status);
  const active = ["running", "queued", "paused"].includes(job.status);
  const scorecardId = generation ? savedEvaluation?.id : job.scorecard && !job.scorecard.error ? job.id : undefined;
  function openDetails() { if (row.current) row.current.open = true; setExpanded(true); }
  async function requestJob(path: string, body?: object) {
    if (working) return;
    setWorking(true); setRequestingEvaluation(path === "/v1/jobs/evaluations");
    try { await (body ? api.request(path, "POST", body) : api.request(path, "POST")); await onChanged(); }
    catch (error) { onError(String(error)); }
    finally { setWorking(false); setRequestingEvaluation(false); }
  }
  async function openBundle() {
    try { setFiles(await api.request<BundleFiles>(`/v1/jobs/${job.id}/files`)); }
    catch (error) { onError(String(error)); }
  }
  async function copyLogPath() {
    try {
      const log = await api.request<{ log_path: string }>(`/v1/jobs/${job.id}/diagnostics`);
      if (!log.log_path) throw new Error("No saved log is available for this job");
      await writePathToClipboard(log.log_path);
    } catch (error) { onError(String(error)); }
  }
  async function remove() {
    if (working || !confirmRemoval) return;
    setWorking(true);
    try {
      if (confirmRemoval === "history") {
        if (onDeleteHistory) { if (await onDeleteHistory() === false) return; }
        else { await api.request(`/v1/jobs/${job.id}/history`, "DELETE"); await onChanged(); }
      } else {
        await api.request(`/v1/jobs/${job.id}/${job.status === "completed" ? "bundle" : "incomplete-bundle"}`, "DELETE");
        await onChanged();
      }
      setConfirmRemoval(null);
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); }
  }
  async function exportBundle() {
    if (exporting) return;
    openDetails(); setExporting(true); setExportProgress(null); setSavedExport(null);
    try {
      const filename = `${name.replace(/[^a-z0-9._-]+/gi, "-")}${job.status === "completed" ? "" : "-partial"}-${job.id.slice(0, 8)}.zip`;
      const result = await api.downloadBundle(job.id, filename, setExportProgress);
      if (result.status === "saved") setSavedExport(result.path);
    } catch (error) { onError(String(error)); }
    finally { setExporting(false); setExportProgress(null); }
  }
  const progress = job.progress;
  const percent = progress && progress.total_hours > 0 ? Math.min(100, Math.round(progress.completed_hours / progress.total_hours * 100)) : null;
  const phase = job.status === "paused" ? "Paused" : job.status === "queued" ? (percent === null ? "Queued" : "Queued to resume") : job.status === "stopped" ? "Stopped" : job.status === "failed" ? "Failed" : job.status === "completed" ? "Completed" : percent === null && progress?.phase === "Queued" ? "Starting" : progress?.phase || "Starting";
  const detail = job.status_message || (job.status === "stopped" ? `Generation stopped before completion. Last report: ${progress?.detail || "none"}` : job.status === "paused" ? `Paused. Last report: ${progress?.detail || "none"}` : progress?.detail || "Waiting to start");
  const name = scenarioName || job.scenario?.split(/[\\/]/).slice(-2, -1)[0] || job.output_root.split(/[\\/]/).slice(-2, -1)[0] || "Run";
  const submitted = jobSubmittedAt(job);
  const scenarioVersion = sourceLabel || (job.scenario_source ? capturedVersion(job.scenario_source) : null);
  const result = job.scorecard?.error || (job.scorecard ? `${job.scorecard.overall_score == null ? "N/A" : `${job.scorecard.overall_score.toFixed(0)}/100`} · ${job.scorecard.acceptance_passed === true ? "Pass" : job.scorecard.acceptance_passed === false ? "Fail" : "Indeterminate"}` : job.status === "running" ? "Evaluating…" : job.status_message || "Waiting");
  const evaluate: ObjectAction = { id: "evaluate", label: savedEvaluation ? "Re-evaluate" : "Evaluate", group: "work", disabled: working || job.status !== "completed" || evaluationActive, reason: working ? "An operation is in progress" : evaluationActive ? "An evaluation for this run is already active" : "Complete generation first", description: "Evaluate captured data; a completed report replaces previous scores", run: () => requestJob("/v1/jobs/evaluations", { generation_id: job.id }) };
  const actions: ObjectAction[] = [
    { id: "open", label: "Open details", group: "inspect", run: openDetails },
    ...(generation ? [{ id: "properties", label: "Properties…", group: "inspect" as const, run: () => setPropertiesOpen(true) }] : []),
    { id: "files", label: "View files", group: "inspect", run: openBundle },
    { id: "scorecard", label: "View scorecard", group: "inspect", disabled: !scorecardId, reason: "Complete an evaluation to save a scorecard", run: () => setScorecardOpen(true) },
    { id: "log", label: "View log", group: "inspect", run: () => { setLogRequested(true); openDetails(); } },
    { id: "hide-log", label: "Hide log", group: "inspect", disabled: !logRequested, reason: "Open the log first", run: () => setLogRequested(false) },
    { id: "refresh-log", label: "Refresh log", group: "inspect", run: () => { setLogRequested(true); setLogRefresh((value) => value + 1); openDetails(); } },
    ...(!generation && job.generation_id ? [{ id: "source", label: "Open generation", group: "inspect" as const, disabled: !onShowSource && !context?.showGeneration, reason: "Open this generation from Job center", run: () => (onShowSource || context?.showGeneration)?.(job.generation_id!) }] : []),
    ...(generation ? [
      { id: "pause", label: "Pause", group: "work" as const, disabled: working || job.status !== "running" || job.checkpoint_hours === 0, reason: job.checkpoint_hours === 0 ? "Checkpointing is disabled for this run" : "Available while generation is running", run: () => requestJob(`/v1/jobs/${job.id}/suspend`) },
      { id: "resume", label: "Resume", group: "work" as const, disabled: working || !job.can_resume || !["paused", "stopped"].includes(job.status), reason: !job.can_resume ? "No usable checkpoint is available" : "Available for a paused or stopped run", run: () => requestJob("/v1/jobs/resume", { generation_id: job.id }) },
    ] : []),
    { id: "stop", label: "Stop", group: "work", disabled: working || !active, reason: "Available for a queued, running or paused job", run: () => requestJob(`/v1/jobs/${job.id}/stop`) },
    ...(generation ? [evaluate, { id: "regenerate", label: "Regenerate", group: "work" as const, disabled: working || !["stopped", "failed", "cancelled"].includes(job.status), reason: "Available after an interrupted generation", run: () => requestJob(`/v1/jobs/${job.id}/regenerate`) }] : []),
    ...(generation ? [{ id: "export", label: job.status === "completed" ? "Export ZIP…" : "Export partial ZIP…", group: "reuse" as const, disabled: exporting || ["running", "queued"].includes(job.status), reason: exporting ? "Export is in progress" : "Pause or complete generation before export", run: exportBundle }] : []),
    { id: "copy-log", label: "Copy log path", group: "reuse", run: copyLogPath },
    { id: "copy", label: "Copy path", group: "reuse", run: () => writePathToClipboard(job.output_root).catch((error) => onError(String(error))) },
    { id: "history", label: "Remove from history", group: "remove", disabled: working || !terminal || removed, reason: removed ? "Already removed from Job center" : "Finish or stop this job first", description: "Keep files and scorecards", run: () => setConfirmRemoval("history") },
    ...(generation && job.owned_output === true ? [{ id: "delete", label: "Delete bundle", group: "remove" as const, disabled: working || evaluationActive || ["running", "queued"].includes(job.status) || (job.status !== "completed" && linked.length > 0), reason: evaluationActive ? "Stop the linked evaluation first" : linked.length ? "This incomplete run has linked evaluations" : "Pause or stop this run first", description: "Delete run files and linked evaluations", run: () => setConfirmRemoval("bundle") }] : []),
  ];
  const shortcutIds = job.status === "running" ? generation ? ["pause", "stop"] : ["stop"] : job.status === "queued" ? ["stop"] : job.status === "paused" ? generation ? ["resume", "stop"] : ["stop"] : generation && job.status === "stopped" && job.can_resume ? ["resume", "files"] : generation && job.status === "completed" ? ["evaluate", "files"] : ["files"];
  return <details ref={row} className={`job-row ${summaryExtra ? "workspace-run" : ""} ${highlighted ? "source-highlight" : ""}`} id={`${idPrefix}-${job.id}`} onToggle={(event) => setExpanded(event.currentTarget.open)}>
    <summary className="job-row-summary" role={onNavigateRow ? "button" : undefined} onClick={onNavigateRow ? (event) => { event.preventDefault(); onNavigateRow(); } : undefined}><span className="job-row-name"><span className="job-row-title"><strong>{grouped ? `Run #${job.id.slice(0, 8)}` : name}</strong>{scenarioVersion && <span className="scenario-version" title="Scenario identity captured by this run">{scenarioVersion}</span>}{latest && <span className="run-latest">Latest</span>}{grouped && sizeBytes != null && <span className="bundle-size" title="Size of bundle contents on disk; ZIP size may differ">{formatBundleSize(sizeBytes)}</span>}</span><small>{job.kind === "evaluation" ? `Evaluates run #${job.generation_id?.slice(0, 8) || "unknown"}` : grouped ? "Generation" : `Run #${job.id.slice(0, 8)}`}</small></span><time className="job-row-time" title={submitted ? new Date(submitted * 1000).toLocaleString() : undefined}>{submitted ? formatTime(submitted) : "Time unknown"}</time><StatusBadge status={jobDisplayStatus(job)} /><span className="job-row-result">{generation ? <><span>{phase} · {percent === null ? "Preparing" : `${percent}%`}</span><span className="progress-track" role="progressbar" aria-valuenow={percent ?? 0} aria-valuemin={0} aria-valuemax={100} aria-label={`${name} generation progress`}><span style={{ width: `${percent ?? 0}%` }} /></span>{(requestingEvaluation || activeEvaluation) && <small className="run-evaluation-state">{requestingEvaluation ? "Queuing evaluation…" : activeEvaluation?.status === "paused" ? "Evaluation paused" : activeEvaluation?.status === "queued" ? "Evaluation queued" : "Evaluation in progress"}</small>}{job.status === "stopped" && !job.can_resume && <small className="run-checkpoint-state">No checkpoint to resume</small>}</> : result}</span>{summaryExtra}<span className="job-row-controls"><span className="job-row-shortcuts">{shortcutIds.map((id) => <ActionShortcut key={id} action={actions.find((entry) => entry.id === id)!} />)}</span><ChevronDown size={16} className="job-row-chevron" /><ObjectMenu label={generation ? `Bundle options for ${job.id}` : `Options for evaluation ${job.id}`} actions={actions} /></span></summary>
    <div className="job-row-details"><div className="path-with-copy job-output-path"><span className="path-value muted" title={job.output_root}>{job.output_root}</span><CopyPathButton path={job.output_root} label="Copy bundle path" onError={onError} /></div>
      {generation && <>{job.input_snapshot && <p className="muted small" title="Includes, exact packs, overlays, and embedded data were captured before this run was queued. Subsequent edits apply to new runs.">Inputs captured {formatTime(submitted)}</p>}<p className="muted small">{detail}</p>{!!progress?.storyline_total && <p className="muted small">Storyline {progress.storyline_event} of {progress.storyline_total}</p>}</>}
      {!generation && job.scorecard && !job.scorecard.error && <p className="muted small">{(job.scorecard.total_records || 0).toLocaleString()} records evaluated</p>}
      {showScorecard && !generation && <ScorecardPanel jobId={job.id} api={api} />}
      {job.status_message && generation && <p className="job-message">{job.status_message}</p>}
      {expanded && <JobDiagnostics job={job} api={api} onError={onError} requestedLog={logRequested} refreshVersion={logRefresh} />}
      {exporting && isTauri() && <ExportStatus progress={exportProgress} api={api} onError={onError} />}
      {savedExport && <div className="path-with-copy muted small"><span className="path-value" title={savedExport}>Saved to {savedExport}</span><CopyPathButton path={savedExport} label="Copy saved ZIP path" onError={onError} /></div>}
      {expanded && detailsExtra}
    </div>
    {propertiesOpen && <BundlePropertiesDialog id={job.id} api={api} onClose={() => setPropertiesOpen(false)} />}
    {files && <BundleFileBrowser jobId={job.id} files={files} api={api} onClose={() => setFiles(null)} onError={onError} />}
    {scorecardOpen && scorecardId && <Dialog.Root open onOpenChange={setScorecardOpen}><Dialog.Portal><Dialog.Overlay className="radix-dialog-overlay" /><Dialog.Content className="close-modal scorecard-dialog"><Dialog.Title>Scorecard</Dialog.Title><Dialog.Description>Saved evaluation of this run's captured data.</Dialog.Description><ScorecardPanel jobId={scorecardId} api={api} /><Dialog.Close className="button-quiet">Close scorecard</Dialog.Close></Dialog.Content></Dialog.Portal></Dialog.Root>}
    {confirmRemoval && <RemovalConfirmation title={confirmRemoval === "history" ? "Remove from history?" : "Delete this bundle?"} label={confirmRemoval === "history" ? "Remove from history" : "Delete bundle"} busy={working} onCancel={() => setConfirmRemoval(null)} onConfirm={remove}><p>{confirmRemoval === "history" ? "This job disappears from Job center. Its run files and saved scorecard remain available." : "The run directory, linked evaluations and their Studio records will be removed. The authored scenario remains available."}</p><div className="path-with-copy"><span className="path-value source-path" title={job.output_root}>{job.output_root}</span><CopyPathButton path={job.output_root} label="Copy bundle path" onError={onError} /></div></RemovalConfirmation>}
  </details>;
}

export function ValidationPanel({ result, onFix, fixing = false, embedded = false }: { result: ValidationResult | undefined; onFix?: () => void; fixing?: boolean; embedded?: boolean }) {
  if (!result) return <div className="empty-panel"><Activity size={28} /><h3>Ready to check</h3><p>Validate this scenario to see actionable findings and a resource forecast.</p></div>;
  const report = result.report;
  if (!report) return embedded ? <p className="error-text" role="alert">{result.error || `CLI exited with code ${result.exit_code}`}</p> : <div className="empty-panel error-text"><h3>Validation could not finish</h3><p>{result.error || `CLI exited with code ${result.exit_code}`}</p></div>;
  const issues = Array.isArray(report.issues) ? report.issues as Record<string, unknown>[] : [];
  const valid = Boolean(report.valid) && result.exit_code === 0;
  const hasWarnings = valid && issues.some((issue) => issue.severity === "warning");
  const scenario = report.scenario as Record<string, unknown> | undefined;
  return <div className="validation-panel">
    {!embedded && <div className={`validation-summary ${valid ? (hasWarnings ? "warning" : "valid") : "invalid"}`}><div className="validation-icon">{valid ? (hasWarnings ? <TriangleAlert size={20} /> : <Check size={20} />) : <X size={20} />}</div><div className="validation-summary-copy"><h3>{valid ? (issues.length ? "Valid with findings" : "Scenario is valid") : "Needs changes"}</h3><p>{String(scenario?.name || "Scenario")} · {issues.length} finding{issues.length === 1 ? "" : "s"}</p></div>{issues.length > 0 && onFix && <button className="button-quiet validation-fix" disabled={fixing} onClick={onFix} title="Open a new conversation with a prepared request and the current findings">Fix in chat</button>}</div>}
    {issues.length === 0 ? valid ? <p className="muted">No validation issues found.</p> : <p className="error-text" role="alert">{result.error || `Validation failed without detailed findings (exit code ${result.exit_code}). Revalidate to check the current files.`}</p> : <div className="findings-list" aria-label="Validation findings">{issues.map((issue, index) => <article className="finding" key={`${index}-${issue.field_path}`}><span className={`severity severity-${issue.severity}`}>{String(issue.severity)}</span><div><h4>{String(issue.field_path || "Scenario")}</h4><p>{String(issue.message || "")}</p>{Boolean(issue.suggestion) && <p className="suggestion">Suggested fix: {String(issue.suggestion)}</p>}</div></article>)}</div>}
  </div>;
}
