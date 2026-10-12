import { useEffect, useState } from "react";
import { ActionShortcut, ObjectMenu, type ObjectAction } from "./ObjectActions";
import { CopyPathButton, writePathToClipboard } from "./CopyPathButton";
import { StudioApi, type StudioJob } from "./api";
import type { components } from "./generated/studio";

type Diagnostics = components["schemas"]["JobDiagnostics"];

export function JobDiagnostics({ job, api, onError, requestedLog = false, refreshVersion = 0 }: {
  job: StudioJob; api: StudioApi; onError: (message: string) => void; requestedLog?: boolean; refreshVersion?: number;
}) {
  const [data, setData] = useState<Diagnostics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showLog, setShowLog] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => { if (requestedLog) setShowLog(true); }, [requestedLog]);
  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    void api.request<Diagnostics>(`/v1/jobs/${encodeURIComponent(job.id)}/diagnostics`)
      .then((value) => { if (!cancelled) setData(value); })
      .catch((reason) => { if (!cancelled) setError(String(reason)); });
    return () => { cancelled = true; };
  }, [api, job.id, job.status, refresh, refreshVersion]);
  const interrupted = ["stopped", "failed"].includes(job.status);
  const actions: ObjectAction[] = [
    { id: "view", label: showLog ? "Hide log" : "View log", group: "inspect", disabled: !data?.available, reason: "No saved log is available", run: () => setShowLog(!showLog) },
    { id: "refresh", label: "Refresh log", group: "inspect", run: () => setRefresh((value) => value + 1) },
    { id: "copy", label: "Copy log path", group: "reuse", disabled: !data?.log_path, reason: "No saved log is available", run: () => writePathToClipboard(data!.log_path).catch((error) => onError(String(error))) },
  ];
  return <section className="job-diagnostics" aria-label="Run diagnostics">
    {interrupted && data?.message && <div className="job-failure-message" role="status">
      <strong>{job.kind === "generation" ? "Generator reported an error" : "Evaluation reported an error"}</strong>
      <p>{data.message}</p>
    </div>}
    {interrupted && data && !data.message && !job.status_message && <p className="muted small">
      The process ended without reporting completion. {data.available ? "Check the saved log below for details." : "No saved log is available."}
    </p>}
    {error && <p className="job-message">Could not read the run log: {error}</p>}
    <div className="job-log-actions"><ActionShortcut action={actions[0]} /><ObjectMenu label={`Log actions for ${job.id}`} actions={actions} /></div>
    {showLog && data && <div className="job-log-preview">
      <div className="path-with-copy muted small"><span className="path-value" title={data.log_path}>{data.log_path}</span><CopyPathButton path={data.log_path} label="Copy log path" onError={onError} /></div>
      {data.truncated && <p className="muted small">Showing the last 32 KiB. The full log is saved at the path above.</p>}
      <pre>{data.tail || "The saved log is empty."}</pre>
    </div>}
  </section>;
}
