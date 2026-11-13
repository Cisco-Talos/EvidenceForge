import { useEffect, useRef, useState } from "react";
import { AlertTriangle, HardDrive, MemoryStick } from "lucide-react";
import type { CatalogItem, PredictionRecord, StudioApi, StudioSnapshot } from "./api";
import { ActionShortcut, ObjectMenu, type ObjectAction } from "./ObjectActions";
import { formatBundleSize, formatTime } from "./components";
import { RequestFeedback, type RequestState } from "./RequestFeedback";

function normalized(path: string): string {
  const canonical = path.replace(/\\/g, "/").replace(/\/$/, "");
  // Windows drive/UNC paths are case-insensitive; POSIX paths retain their case.
  return /^[a-z]:[/\\]/i.test(path) || path.startsWith("\\\\") ? canonical.toLowerCase() : canonical;
}

function destinationFor(snapshot: StudioSnapshot): string {
  const workspace = normalized(snapshot.settings.workspace);
  const selected = Object.entries(snapshot.settings.output_parents).find(([path]) => normalized(path) === workspace);
  return selected?.[1] || `${snapshot.settings.workspace}/runs`;
}

export function currentPrediction(item: CatalogItem, snapshot: StudioSnapshot): PredictionRecord | undefined {
  if (snapshot.starter_drafts?.includes(item.id)) return undefined;
  const record = snapshot.forecasts?.[item.id];
  const destination = destinationFor(snapshot);
  return record && record.source_sha256 === item.source_sha256
    && record.dependency_fingerprint === snapshot.dependencies?.[item.id]?.fingerprint
    && record.result.checkpoint_hours === snapshot.settings.checkpoint_hours
    && normalized(record.result.destination) === normalized(destination) ? record : undefined;
}

export function ResourceForecastPanel({ item, snapshot, api, onError, onChanged, compact = false }: {
  item: CatalogItem; snapshot: StudioSnapshot; api: StudioApi; onError: (message: string) => void;
  onChanged: () => Promise<void>; compact?: boolean;
}) {
  const [refreshing, setRefreshing] = useState(false);
  const [feedback, setFeedback] = useState<RequestState>({ pending: false });
  const record = currentPrediction(item, snapshot);
  const identity = `${item.id}:${item.source_sha256}:${snapshot.settings.workspace}:${snapshot.dependencies?.[item.id]?.fingerprint}:${snapshot.settings.checkpoint_hours}:${destinationFor(snapshot)}`;
  const retained = useRef({ identity, record });
  const currentIdentity = useRef(identity);
  currentIdentity.current = identity;
  useEffect(() => { retained.current = { identity, record }; setFeedback({ pending: false }); setRefreshing(false); }, [identity]);
  if (record?.result.available) retained.current = { identity, record };
  const shown = (refreshing || feedback.error) && !record?.result.available && retained.current.identity === identity ? retained.current.record : record;
  const forecast = shown?.result.forecast;
  async function refresh() {
    if (refreshing) return;
    setRefreshing(true);
    setFeedback({ pending: true });
    const requestedIdentity = identity;
    try {
      const next = await api.request<PredictionRecord>(`/v1/scenarios/${item.id}/resources/predict`, "POST", undefined, 180000);
      if (currentIdentity.current !== requestedIdentity) return;
      await onChanged();
      if (currentIdentity.current !== requestedIdentity) return;
      setFeedback(next.result?.available === false
        ? { pending: false, error: next.result.error || "Resource forecast is unavailable." }
        : { pending: false, completedAt: Date.now() / 1000 });
    } catch (error) { if (currentIdentity.current === requestedIdentity) { setFeedback({ pending: false, error: String(error) }); onError(String(error)); } }
    finally { if (currentIdentity.current === requestedIdentity) setRefreshing(false); }
  }
  const refreshAction: ObjectAction = { id: "refresh", label: "Refresh resource forecast", group: "work", disabled: refreshing, reason: "Forecast refresh is in progress", description: "Recheck current files and available resources", run: refresh };
  return <section className={`surface resource-forecast ${compact ? "compact" : ""}`} aria-label="Generation resource forecast">
    <div className="surface-heading"><h2>{compact ? "Resource forecast" : "Before you generate"}</h2><div className="job-actions"><ActionShortcut action={refreshAction} /><ObjectMenu label="Resource forecast actions" actions={[refreshAction]} /></div></div>
    <RequestFeedback {...feedback} label="Updating estimate…" completedLabel="Checked" previousLabel={forecast ? "Previous estimate is shown below." : undefined} />
    {forecast && shown?.result.available ? <><p className="muted forecast-note">Estimates for this revision · {snapshot.settings.checkpoint_hours ? `checkpoints every ${snapshot.settings.checkpoint_hours} simulated hours` : "checkpoints disabled"}</p><div className="forecast-metrics">{([
      ["Generated data", forecast.final_output, HardDrive], ["Peak memory", forecast.memory, MemoryStick], ["Peak disk", forecast.disk, HardDrive],
    ] as const).map(([label, range, Icon]) => <div key={label}><span><Icon size={14} /> {label}</span><strong>{formatBundleSize(range.expected_bytes)}</strong>{!compact && <small>{formatBundleSize(range.lower_bytes)} – {formatBundleSize(range.upper_bytes)}</small>}</div>)}</div>
      {(forecast.pressures || []).map((pressure) => <p className={`forecast-pressure ${pressure.level}`} key={pressure.resource}><AlertTriangle size={15} /> {pressure.level[0].toUpperCase() + pressure.level.slice(1)} {pressure.resource} pressure: expected use is {(pressure.ratio * 100).toFixed(0)}% of usable capacity.</p>)}
      {!compact && <details className="forecast-details"><summary>Capacity and estimate details</summary><p>Available memory: {formatBundleSize(forecast.snapshot.available_memory_bytes)} + {formatBundleSize(forecast.snapshot.free_swap_bytes)} swap</p><p>Available disk: {formatBundleSize(forecast.snapshot.free_disk_bytes)} · temporary/checkpoint workspace estimate: {formatBundleSize(forecast.checkpoint_workspace?.expected_bytes || 0)}</p><p>Model v{forecast.calibration_version}: {forecast.calibration_label}. Checked {formatTime(shown.completed_at)}.</p><p>Peak disk includes temporary files and checkpoints. Actual size and memory may differ. This estimate does not certify scenario validity or account for every other active process.</p></details>}
    </> : <p className="muted" role="status">{record?.result.error ? `Estimate unavailable: ${record.result.error}` : "Calculating an estimate for the current scenario…"}</p>}
  </section>;
}
