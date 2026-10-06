import { useState } from "react";
import { AlertTriangle, HardDrive, MemoryStick, RefreshCw } from "lucide-react";
import type { CatalogItem, PredictionRecord, StudioApi, StudioSnapshot } from "./api";
import { formatBundleSize, formatTime } from "./components";

function normalized(path: string): string { return path.replace(/\\/g, "/").replace(/\/$/, ""); }

export function currentPrediction(item: CatalogItem, snapshot: StudioSnapshot): PredictionRecord | undefined {
  const record = snapshot.forecasts?.[item.id];
  const destination = snapshot.settings.output_parents[snapshot.settings.workspace] || `${snapshot.settings.workspace}/runs`;
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
  const record = currentPrediction(item, snapshot);
  const forecast = record?.result.forecast;
  async function refresh() {
    setRefreshing(true);
    try {
      await api.request(`/v1/scenarios/${item.id}/resources/predict`, "POST", undefined, 180000);
      await onChanged();
    } catch (error) { onError(String(error)); }
    finally { setRefreshing(false); }
  }
  return <section className={`surface resource-forecast ${compact ? "compact" : ""}`} aria-label="Generation resource forecast">
    <div className="surface-heading"><h2>{compact ? "Resource forecast" : "Before you generate"}</h2><button className="icon-button" aria-label="Refresh resource forecast" title="Recheck current files and available resources" disabled={refreshing} onClick={() => void refresh()}><RefreshCw size={16} className={refreshing ? "spinning" : ""} /></button></div>
    {forecast && record?.result.available ? <><p className="muted forecast-note">Estimates for this revision · {snapshot.settings.checkpoint_hours ? `checkpoints every ${snapshot.settings.checkpoint_hours} simulated hours` : "checkpoints disabled"}</p><div className="forecast-metrics">{([
      ["Generated data", forecast.final_output, HardDrive], ["Peak memory", forecast.memory, MemoryStick], ["Peak disk", forecast.disk, HardDrive],
    ] as const).map(([label, range, Icon]) => <div key={label}><span><Icon size={14} /> {label}</span><strong>{formatBundleSize(range.expected_bytes)}</strong>{!compact && <small>{formatBundleSize(range.lower_bytes)} – {formatBundleSize(range.upper_bytes)}</small>}</div>)}</div>
      {(forecast.pressures || []).map((pressure) => <p className={`forecast-pressure ${pressure.level}`} key={pressure.resource}><AlertTriangle size={15} /> {pressure.level[0].toUpperCase() + pressure.level.slice(1)} {pressure.resource} pressure: expected use is {(pressure.ratio * 100).toFixed(0)}% of usable capacity.</p>)}
      {!compact && <details className="forecast-details"><summary>Capacity and estimate details</summary><p>Available memory: {formatBundleSize(forecast.snapshot.available_memory_bytes)} + {formatBundleSize(forecast.snapshot.free_swap_bytes)} swap</p><p>Available disk: {formatBundleSize(forecast.snapshot.free_disk_bytes)} · temporary/checkpoint workspace estimate: {formatBundleSize(forecast.checkpoint_workspace?.expected_bytes || 0)}</p><p>Model v{forecast.calibration_version}: {forecast.calibration_label}. Checked {formatTime(record.completed_at)}.</p><p>Peak disk includes temporary files and checkpoints. Actual size and memory may differ. This estimate does not certify scenario validity or account for every other active process.</p></details>}
    </> : <p className="muted" role="status">{record?.result.error ? `Estimate unavailable: ${record.result.error}` : "Calculating an estimate for the current scenario…"}</p>}
  </section>;
}
