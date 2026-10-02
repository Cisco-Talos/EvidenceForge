import { useState } from "react";
import { FileCode2, SquarePen } from "lucide-react";
import type { CatalogItem, EnvironmentReport, StudioApi } from "./api";
import { BundleFileBrowser } from "./BundleFileBrowser";
import { CopyPathButton } from "./CopyPathButton";
import { InspectionSection } from "./InspectionSection";

export function ConfigurationLayers({ item, report, api, onRefresh, onPrepare, onError }: {
  item: CatalogItem; report: EnvironmentReport; api: StudioApi; onRefresh: () => void;
  onPrepare: (prompt: string) => Promise<void>; onError: (message: string) => void;
}) {
  const [working, setWorking] = useState(false);
  const [viewer, setViewer] = useState<{ scopeId: string; root: string; path: string; size: number } | null>(null);
  const configuration = report.configuration;
  async function toggle(scope: string, enabled: boolean) {
    setWorking(true);
    try {
      if (scope === "project" && item.project_id) await api.request(`/v1/projects/${item.project_id}`, "PATCH", { overlay_enabled: enabled });
      else await api.request(`/v1/scenarios/${item.id}/configuration`, "POST", { scenario_enabled: enabled });
      onRefresh();
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); }
  }
  return <>{!configuration && <p className="field-error" role="alert">Configuration could not be inspected. Restore the selected context and directories, then refresh.</p>}<InspectionSection title="Configuration layers" count={configuration ? `${configuration.scopes.filter((scope) => scope.enabled).length} enabled · ${configuration.scopes.length} layers` : "Unavailable"} className="configuration-layers">
    <p className="muted">Applied in order, using each family’s merge rules. Turning a layer off preserves its files. Existing runs keep their captured configuration.</p>
    {configuration ? <>
      <div className="configuration-scope-list">{configuration.scopes.map((scope) => <div className="configuration-scope" key={scope.id}>
        <div className="configuration-scope-heading"><strong>{scope.name}</strong>{["project", "scenario"].includes(scope.id) ? <label title={scope.id === "project" ? "Applies to all scenarios assigned to this project" : "Applies only to this scenario"}><input type="checkbox" aria-label={`Use ${scope.name} configuration`} checked={scope.enabled} disabled={working} onChange={(event) => void toggle(scope.id, event.target.checked)} /> Enabled</label> : <small>{scope.enabled ? "Enabled" : "Disabled"}</small>}</div>
        <div className="path-with-copy"><span className="path-value source-path">{scope.root}</span><CopyPathButton path={scope.root} label={`Copy ${scope.name} configuration path`} onError={onError} /></div>
        <div className="configuration-scope-actions"><small>{scope.files?.length || 0} files{scope.truncated ? " (first 500)" : ""}</small><button className="button-quiet" disabled={working} onClick={() => void onPrepare(`Please use the eforge-config workflow to inspect and help edit the ${scope.name} configuration at ${scope.root}. ${configuration.context_path ? `This scenario explicitly selects --context ${configuration.context_path}.` : `Use --project-root ${item.workspace}.`} Explain the existing family merge rules and propose changes before editing. Preserve other layers and validate the selected context in a fresh process afterward.`).catch((error) => onError(String(error)))}><SquarePen size={14} /> Edit in chat</button></div>
        {!!scope.files?.length && <details><summary>View configuration files</summary><ul className="overlay-file-list">{scope.files.map((file) => <li key={file.path}><button onClick={() => setViewer({ scopeId: scope.id, root: scope.root, ...file })}><FileCode2 size={15} /><span>{file.path}</span></button></li>)}</ul></details>}
      </div>)}</div>
      <details className="configuration-cli"><summary>Use this configuration outside Studio</summary><p>Pass the same selection to info, validate-config, validate, resolve, resources predict, or generate.</p>{configuration.context_path && <div className="path-with-copy"><span className="path-value source-path">{configuration.context_path}</span><CopyPathButton path={configuration.context_path} label="Copy configuration context path" onError={onError} /></div>}<div className="path-with-copy"><code className="path-value">{configuration.cli_command}</code><CopyPathButton path={configuration.cli_command} label="Copy generation command" onError={onError} /></div></details>
    </> : <p className="field-error">Configuration could not be inspected. Restore the selected context and directories, then refresh.</p>}
    {viewer && <BundleFileBrowser kind="environment" jobId={`${item.id}/layers/${viewer.scopeId}`} files={{ root: viewer.root, files: [{ path: viewer.path, size: viewer.size }], truncated: false }} api={api} onClose={() => setViewer(null)} onError={onError} />}
  </InspectionSection></>;
}
