import { useState } from "react";
import { Download, RefreshCw } from "lucide-react";
import type { DependencyHealth, StudioApi } from "./api";
import { DependencyRows } from "./ImportDialog";

export function DependencyPanel({ itemId, health, api, onChanged, onImport }: { itemId: string; health?: DependencyHealth; api: StudioApi; onChanged: () => Promise<void>; onImport: () => void }) {
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function refresh() {
    setWorking(true); setError(null);
    try { await api.request(`/v1/scenarios/${itemId}/dependencies/refresh`, "POST", undefined, 180000); await onChanged(); }
    catch (failure) { setError(String(failure)); }
    finally { setWorking(false); }
  }
  return <section className={`dependency-panel ${health?.ready === false ? "dependencies-missing" : ""}`} aria-label="Scenario dependencies"><header><div><strong>{!health ? "Dependencies" : health.ready ? "Dependencies ready" : "Dependency errors"}</strong><small>{health?.ready === false ? "Import the required pack versions or repair the listed files before generating." : "Uses current files; refreshed automatically after pack and scenario changes."}</small></div><button className="icon-button" aria-label="Refresh dependencies" title="Refresh dependencies from disk" disabled={working} onClick={() => void refresh()}><RefreshCw size={16} className={working ? "spinning" : ""} /></button>{health?.rows.some((row) => row.kind === "pack" && ["missing", "conflict"].includes(row.status)) && <button className="button-quiet" onClick={onImport}><Download size={15} /> Import packs</button>}</header>{health?.rows.length ? <details open={!health.ready}><summary>{health.rows.length} dependency {health.rows.length === 1 ? "check" : "checks"}</summary><DependencyRows rows={health.rows} /></details> : null}{error && <p className="field-error" role="alert">{error}</p>}</section>;
}
