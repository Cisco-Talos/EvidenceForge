import { InspectionSection } from "./InspectionSection";
import { useEffect, useState } from "react";
import { Activity, Check, ChevronDown, CircleHelp, ClipboardCheck, Download, FolderOpen, MessageSquareText, Pause, Play, RotateCcw, Trash2, TriangleAlert, X } from "lucide-react";
import { DropdownMenu, Tooltip } from "radix-ui";
import { isTauri } from "@tauri-apps/api/core";
import { StudioApi, StudioJob, ValidationResult, type ExportProgress } from "./api";
import { BundleFileBrowser, type BundleFiles } from "./BundleFileBrowser";
import { CopyPathButton } from "./CopyPathButton";
import { ExportStatus } from "./ExportStatus";
import { jobSubmittedAt } from "./jobOrder";
import { ScorecardPanel } from "./ScorecardPanel";

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

export function JobCard({ job, name: scenarioName, grouped = false, sizeBytes, highlighted = false, focusScorecard = false, onShowSource, onDeleteHistory, api, onError, onChanged, idPrefix = "job" }: {
  job: StudioJob; name?: string; grouped?: boolean; sizeBytes?: number | null; highlighted?: boolean; focusScorecard?: boolean;
  onShowSource?: (generationId: string) => void; api: StudioApi;
  onDeleteHistory?: () => Promise<void>;
  onError: (message: string) => void; onChanged: () => Promise<void>; idPrefix?: string;
}) {
  const [files, setFiles] = useState<BundleFiles | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [working, setWorking] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportProgress, setExportProgress] = useState<ExportProgress | null>(null);
  const [savedExport, setSavedExport] = useState<string | null>(null);
  const [showScorecard, setShowScorecard] = useState(focusScorecard);
  useEffect(() => { if (focusScorecard) setShowScorecard(true); }, [focusScorecard]);
  async function openBundle() {
    try {
      setFiles(await api.request<BundleFiles>(`/v1/jobs/${job.id}/files`));
    } catch (error) { onError(String(error)); }
  }
  async function regenerate() {
    setWorking(true);
    try {
      await api.request(`/v1/jobs/${job.id}/regenerate`, "POST");
      await onChanged();
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); }
  }
  async function deleteBundle() {
    setWorking(true);
    try {
      await api.request(`/v1/jobs/${job.id}/${job.status === "completed" ? "bundle" : "incomplete-bundle"}`, "DELETE");
      setConfirmDelete(false);
      await onChanged();
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); }
  }
  async function exportBundle() {
    setExporting(true);
    setExportProgress(null);
    setSavedExport(null);
    try {
      const filename = `${name.replace(/[^a-z0-9._-]+/gi, "-")}${job.status === "completed" ? "" : "-partial"}-${job.id.slice(0, 8)}.zip`;
      const result = await api.downloadBundle(job.id, filename, setExportProgress);
      if (result.status === "saved") setSavedExport(result.path);
    } catch (error) { onError(String(error)); }
    finally { setExporting(false); setExportProgress(null); }
  }
  const progress = job.progress;
  const percent = progress && progress.total_hours > 0
    ? Math.min(100, Math.round(progress.completed_hours / progress.total_hours * 100)) : null;
  const phase = job.status === "paused" ? "Paused"
    : job.status === "queued" ? (percent === null ? "Queued" : "Queued to resume")
    : job.status === "stopped" ? "Stopped"
    : job.status === "failed" ? "Failed"
    : job.status === "completed" ? "Completed"
    : percent === null && progress?.phase === "Queued" ? "Starting" : progress?.phase || "Starting";
  const detail = job.status_message
    || (job.status === "stopped" ? `Generation stopped before completion. Last report: ${progress?.detail || "none"}`
      : job.status === "paused" ? `Paused. Last report: ${progress?.detail || "none"}`
      : progress?.detail || "Waiting to start");
  const name = scenarioName || job.scenario?.split(/[\\/]/).slice(-2, -1)[0]
    || job.output_root.split(/[\\/]/).slice(-2, -1)[0] || "Run";
  const submitted = jobSubmittedAt(job);
  const canDeleteHistory = !!onDeleteHistory && ["completed", "stopped", "failed", "cancelled"].includes(job.status);
  const canDeleteBundle = job.kind === "generation" && !["running", "queued"].includes(job.status);
  const result = job.scorecard?.error || (job.scorecard
    ? `${job.scorecard.overall_score == null ? "N/A" : `${job.scorecard.overall_score.toFixed(0)}/100`} · ${job.scorecard.acceptance_passed === true ? "Pass" : job.scorecard.acceptance_passed === false ? "Fail" : "Indeterminate"}`
    : job.status === "running" ? "Evaluating…" : job.status_message || "Waiting");
  return <details className={`job-row ${highlighted ? "source-highlight" : ""}`} id={`${idPrefix}-${job.id}`}>
    <summary className="job-row-summary"><span className="job-row-name"><span className="job-row-title"><strong>{grouped ? `Run #${job.id.slice(0, 8)}` : name}</strong>{grouped && sizeBytes != null && <span className="bundle-size" title="Size of bundle contents on disk; ZIP size may differ">{formatBundleSize(sizeBytes)}</span>}</span><small>{job.kind === "evaluation" ? `Evaluates run #${job.generation_id?.slice(0, 8) || "unknown"}` : grouped ? "Generation" : `Run #${job.id.slice(0, 8)}`}</small></span><time className="job-row-time" title={submitted ? new Date(submitted * 1000).toLocaleString() : undefined}>{submitted ? formatTime(submitted) : "Time unknown"}</time><StatusBadge status={job.status} /><span className="job-row-result">{job.kind === "generation" ? <><span>{phase} · {percent === null ? "Preparing" : `${percent}%`}</span><span className="progress-track" role="progressbar" aria-valuenow={percent ?? 0} aria-valuemin={0} aria-valuemax={100} aria-label={`${name} generation progress`}><span style={{ width: `${percent ?? 0}%` }} /></span></> : result}</span><ChevronDown size={16} className="job-row-chevron" /></summary>
    <div className="job-row-details"><div className="path-with-copy job-output-path"><span className="path-value muted" title={job.output_root}>{job.output_root}</span><CopyPathButton path={job.output_root} label="Copy bundle path" onError={onError} /></div>
      {job.kind === "generation" && <>{job.input_snapshot && <p className="muted small" title="Includes, exact packs, overlays, and embedded data were captured before this run was queued. Subsequent edits apply to new runs.">Inputs captured {formatTime(submitted)}</p>}<p className="muted small">{detail}</p>{!!progress?.storyline_total && <p className="muted small">Storyline {progress.storyline_event} of {progress.storyline_total}</p>}</>}
      {job.kind === "evaluation" && job.scorecard && !job.scorecard.error && <p className="muted small">{(job.scorecard.total_records || 0).toLocaleString()} records evaluated</p>}
      {job.kind === "evaluation" && job.scorecard && !job.scorecard.error && <button className="job-source-link" aria-expanded={showScorecard} onClick={() => setShowScorecard(!showScorecard)}>{showScorecard ? "Hide scorecard" : "View scorecard"}</button>}
      {showScorecard && job.kind === "evaluation" && <ScorecardPanel jobId={job.id} api={api} />}
      {job.kind === "evaluation" && job.generation_id && onShowSource && <button className="job-source-link" onClick={() => onShowSource(job.generation_id!)}>Jump to generation #{job.generation_id.slice(0, 8)}</button>}
      {job.status_message && job.kind === "generation" && <p className="job-message">{job.status_message}</p>}
    <div className="job-actions">
      <button className="button-quiet" onClick={() => void openBundle()}><FolderOpen size={16} /> View files</button>
      {job.kind === "generation" && !["running", "queued"].includes(job.status) && <button className="button-quiet" disabled={exporting} onClick={() => void exportBundle()}><Download size={16} /> {exporting ? "Exporting…" : job.status === "completed" ? (isTauri() ? "Export ZIP" : "Download ZIP") : (isTauri() ? "Export partial ZIP" : "Download partial ZIP")}</button>}
      {job.kind === "generation" && job.status === "running" && <button className="button-quiet" onClick={() => void api.request(`/v1/jobs/${job.id}/suspend`, "POST").catch((error) => onError(String(error)))}><Pause size={16} /> Suspend</button>}
      {job.kind === "generation" && job.status === "completed" && <button className="button-quiet" onClick={() => void api.request("/v1/jobs/evaluations", "POST", { generation_id: job.id }).catch((error) => onError(String(error)))}><ClipboardCheck size={16} /> Evaluate</button>}
      {job.kind === "generation" && ["paused", "stopped"].includes(job.status) && (job.can_resume
        ? <button className="button-quiet" onClick={() => void api.request("/v1/jobs/resume", "POST", { generation_id: job.id }).catch((error) => onError(String(error)))}><Play size={16} /> Resume</button>
        : <span className="muted small" title="The run stopped before a usable checkpoint was saved">No checkpoint to resume</span>)}
      {job.kind === "generation" && ["stopped", "failed", "cancelled"].includes(job.status) && <button className="button-quiet" disabled={working} onClick={() => void regenerate()}><RotateCcw size={16} /> Regenerate</button>}
      {(canDeleteHistory || canDeleteBundle) && <DropdownMenu.Root><DropdownMenu.Trigger className="button-quiet job-delete-trigger" disabled={working}><Trash2 size={16} /> Delete <ChevronDown size={13} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu job-delete-menu" sideOffset={5} align="end">
        {canDeleteHistory && <DropdownMenu.Item onSelect={() => { setWorking(true); void onDeleteHistory!().finally(() => setWorking(false)); }}><strong>Delete job</strong><small>Remove from Job center; keep its files and scorecard.</small></DropdownMenu.Item>}
        {canDeleteBundle && <DropdownMenu.Item onSelect={() => setConfirmDelete(true)}><strong>Delete bundle…</strong><small>Remove the run’s files and linked evaluations.</small></DropdownMenu.Item>}
      </DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>}
    </div>
    {exporting && isTauri() && <ExportStatus progress={exportProgress} api={api} onError={onError} />}
    {savedExport && <div className="path-with-copy muted small"><span className="path-value" title={savedExport}>Saved to {savedExport}</span><CopyPathButton path={savedExport} label="Copy saved ZIP path" onError={onError} /></div>}
    </div>
    {files && <BundleFileBrowser jobId={job.id} files={files} api={api} onClose={() => setFiles(null)} onError={onError} />}
    {confirmDelete && <div className="modal-backdrop"><div className="close-modal" role="dialog" aria-modal="true" aria-label="Delete bundle"><h2>Delete this bundle?</h2><p>The run directory, linked evaluation reports, and their Studio records will be removed. The authored scenario remains available.</p><div className="path-with-copy"><span className="path-value source-path" title={job.output_root}>{job.output_root}</span><CopyPathButton path={job.output_root} label="Copy bundle path" onError={onError} /></div><div className="close-modal-actions"><button className="button-quiet" onClick={() => setConfirmDelete(false)}>Cancel</button><button className="button-danger" disabled={working} onClick={() => void deleteBundle()}>Delete bundle</button></div></div></div>}
  </details>;
}

export function ValidationPanel({ result, onFix, fixing = false }: { result: ValidationResult | undefined; onFix?: () => void; fixing?: boolean }) {
  if (!result) return <div className="empty-panel"><Activity size={28} /><h3>Ready to check</h3><p>Validate this scenario to see actionable findings and a resource forecast.</p></div>;
  const report = result.report;
  if (!report) return <div className="empty-panel error-text"><h3>Validation could not finish</h3><p>{result.error || `CLI exited with code ${result.exit_code}`}</p></div>;
  const issues = Array.isArray(report.issues) ? report.issues as Record<string, unknown>[] : [];
  const valid = Boolean(report.valid);
  const hasWarnings = valid && issues.some((issue) => issue.severity === "warning");
  const scenario = report.scenario as Record<string, unknown> | undefined;
  return <div className="validation-panel">
    <div className={`validation-summary ${valid ? (hasWarnings ? "warning" : "valid") : "invalid"}`}><div className="validation-icon">{valid ? (hasWarnings ? <TriangleAlert size={20} /> : <Check size={20} />) : <X size={20} />}</div><div className="validation-summary-copy"><h3>{valid ? (issues.length ? "Valid with findings" : "Scenario is valid") : "Needs changes"}</h3><p>{String(scenario?.name || "Scenario")} · {issues.length} finding{issues.length === 1 ? "" : "s"}</p></div>{issues.length > 0 && onFix && <button className="button-quiet validation-fix" disabled={fixing} onClick={onFix} title="Open a new conversation with a prepared request and the current findings"><MessageSquareText size={16} /> Fix in chat</button>}</div>
    {issues.length === 0 ? <p className="muted">No validation issues found.</p> : <InspectionSection title="Validation findings" count={`${issues.length} finding${issues.length === 1 ? "" : "s"}`}><div className="findings-list">{issues.map((issue, index) => <article className="finding" key={`${index}-${issue.field_path}`}><span className={`severity severity-${issue.severity}`}>{String(issue.severity)}</span><div><h4>{String(issue.field_path || "Scenario")}</h4><p>{String(issue.message || "")}</p>{Boolean(issue.suggestion) && <p className="suggestion">Suggested fix: {String(issue.suggestion)}</p>}</div></article>)}</div></InspectionSection>}
  </div>;
}
