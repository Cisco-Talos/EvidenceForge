import { useEffect, useRef, useState } from "react";
import { CopyPathButton } from "./CopyPathButton";
import { StudioApi, type StudioJob } from "./api";
import type { components } from "./generated/studio";
import { RequestFeedback } from "./RequestFeedback";

type Diagnostics = components["schemas"]["JobDiagnostics"];

export function JobDiagnostics({ job, api, onError, requestedLog = false, refreshVersion = 0, onLoading }: {
  job: StudioJob; api: StudioApi; onError: (message: string) => void; requestedLog?: boolean; refreshVersion?: number;
  onLoading?: (loading: boolean) => void;
}) {
  const [data, setData] = useState<Diagnostics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [completedAt, setCompletedAt] = useState<number>();
  const identity = useRef(job.id);
  useEffect(() => {
    let cancelled = false;
    if (identity.current !== job.id) { setData(null); setCompletedAt(undefined); identity.current = job.id; }
    setLoading(true);
    onLoading?.(true);
    setError(null);
    void api.request<Diagnostics>(`/v1/jobs/${encodeURIComponent(job.id)}/diagnostics`)
      .then((value) => { if (!cancelled) { setData(value); setCompletedAt(Date.now() / 1000); } })
      .catch((reason) => { if (!cancelled) setError(String(reason)); })
      .finally(() => { if (!cancelled) { setLoading(false); onLoading?.(false); } });
    return () => { cancelled = true; onLoading?.(false); };
  }, [api, job.id, job.status, refreshVersion]);
  const interrupted = ["stopped", "failed"].includes(job.status);
  return <section className="job-diagnostics" aria-label="Run diagnostics">
    {!loading && !error && interrupted && data?.message && <div className="job-failure-message" role="status">
      <strong>{job.kind === "generation" ? "Generator reported an error" : "Evaluation reported an error"}</strong>
      <p>{data.message}</p>
    </div>}
    {!loading && !error && interrupted && data && !data.message && !job.status_message && <p className="muted small">
      The process ended without reporting completion. {data.available ? "Check the saved log below for details." : "No saved log is available."}
    </p>}
    {requestedLog && <RequestFeedback pending={loading} label="Refreshing log…" error={error ? `Could not read the run log: ${error}` : undefined} completedAt={completedAt} previousLabel={data ? "Previous log preview is shown below." : undefined} />}
    {!requestedLog && error && <p className="job-message" role="alert">Could not read the run log: {error}</p>}
    {requestedLog && data && <div className="job-log-preview">
      <div className="path-with-copy muted small"><span className="path-value" title={data.log_path}>{data.log_path}</span><CopyPathButton path={data.log_path} label="Copy log path" onError={onError} /></div>
      {data.truncated && <p className="muted small">Showing the last 32 KiB. The full log is saved at the path above.</p>}
      <pre>{data.tail || "The saved log is empty."}</pre>
    </div>}
  </section>;
}
