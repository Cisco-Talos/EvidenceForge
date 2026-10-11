import { useEffect, useState } from "react";
import { CopyPathButton } from "./CopyPathButton";
import { StudioApi, type StudioJob } from "./api";
import type { components } from "./generated/studio";

type Diagnostics = components["schemas"]["JobDiagnostics"];

export function JobDiagnostics({ job, api, onError }: {
  job: StudioJob; api: StudioApi; onError: (message: string) => void;
}) {
  const [data, setData] = useState<Diagnostics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showLog, setShowLog] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    void api.request<Diagnostics>(`/v1/jobs/${encodeURIComponent(job.id)}/diagnostics`)
      .then((value) => { if (!cancelled) setData(value); })
      .catch((reason) => { if (!cancelled) setError(String(reason)); });
    return () => { cancelled = true; };
  }, [api, job.id, job.status, refresh]);
  const interrupted = ["stopped", "failed"].includes(job.status);
  return <section className="job-diagnostics" aria-label="Run diagnostics">
    {interrupted && data?.message && <div className="job-failure-message" role="status">
      <strong>{job.kind === "generation" ? "Generator reported an error" : "Evaluation reported an error"}</strong>
      <p>{data.message}</p>
    </div>}
    {interrupted && data && !data.message && !job.status_message && <p className="muted small">
      The process ended without reporting completion. {data.available ? "Check the saved log below for details." : "No saved log is available."}
    </p>}
    {error && <p className="job-message">Could not read the run log: {error}</p>}
    <div className="job-log-actions">
      <button className="button-quiet" disabled={!data?.available} aria-expanded={showLog} onClick={() => setShowLog(!showLog)}>{data ? showLog ? "Hide log" : "View log" : error ? "Log unavailable" : "Reading log…"}</button>
      <button className="button-quiet" onClick={() => setRefresh((value) => value + 1)}>Refresh log</button>
    </div>
    {showLog && data && <div className="job-log-preview">
      <div className="path-with-copy muted small"><span className="path-value" title={data.log_path}>{data.log_path}</span><CopyPathButton path={data.log_path} label="Copy log path" onError={onError} /></div>
      {data.truncated && <p className="muted small">Showing the last 32 KiB. The full log is saved at the path above.</p>}
      <pre>{data.tail || "The saved log is empty."}</pre>
    </div>}
  </section>;
}
