import type { ExportProgress, StudioApi } from "./api";

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

export function ExportStatus({ progress, api, onError }: {
  progress: ExportProgress | null; api: StudioApi; onError: (message: string) => void;
}) {
  const percent = progress?.total ? Math.min(100, Math.round(progress.bytes / progress.total * 100)) : null;
  return <div className="export-status" role="status">
    <span>{progress && (progress.bytes > 0 || progress.total) ? `Saving ${size(progress.bytes)}${progress.total ? ` of ${size(progress.total)}` : ""}` : "Preparing export…"}</span>
    {progress && <><div className="progress-track" role="progressbar" aria-label="Export progress" aria-valuenow={percent ?? undefined} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${percent ?? 0}%` }} /></div><button className="button-quiet" onClick={() => void api.cancelExport(progress.id).catch((error) => onError(String(error)))}>Cancel export</button></>}
  </div>;
}
