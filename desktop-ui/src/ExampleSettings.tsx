import { useEffect, useState } from "react";
import { FolderOpen } from "lucide-react";
import type { components } from "./generated/studio";
import type { StudioApi } from "./api";
import { CopyPathButton } from "./CopyPathButton";
import { ErrorBanner } from "./Feedback";
import { Help, shortPath } from "./components";

type Status = components["schemas"]["ExamplesStatus"];

/** Settings → Workspace row that installs or updates the bundled example scenarios. */
export function ExampleSettings({ workspace, api, onSaved, onOpenFolder, onError, onNotice }: {
  workspace: string; api: StudioApi; onSaved: () => Promise<void>;
  onOpenFolder: (path: string) => Promise<void>; onError: (message: string) => void;
  onNotice: (message: string) => void;
}) {
  const [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setStatus(null); setError("");
    void api.request<Status>("/v1/examples").then((result) => {
      if (live) setStatus(result);
    }).catch((failure) => { if (live) setError(String(failure)); });
    return () => { live = false; };
  }, [api, workspace]);

  async function install() {
    setBusy(true); setError("");
    try {
      const result = await api.request<Status>("/v1/examples/install", "POST", { workspace }, 180000);
      setStatus(result);
      if (!result.error) onNotice(result.bundled_releases ? "Examples are up to date in this workspace." : "Examples project is ready. This release has no examples yet.");
      await onSaved();
    } catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }

  const failure = error || status?.error;
  const help = status?.automatic_updates
    ? "Installs the bundled examples here, restoring any you removed; new versions arrive automatically while the examples project exists."
    : "Installs or updates the bundled examples in this workspace, restoring any you removed.";
  return <section aria-label="Example scenarios">
    <div className="setting-row">
      <div className="setting-copy"><strong>Example scenarios</strong><Help text={help} /></div>
      <div className="setting-control">
        {status?.directory && <>
          <span className="path-label" title={status.directory}>{shortPath(status.directory)}</span>
          <CopyPathButton path={status.directory} label="Copy bundled examples path" onError={onError} />
          <button className="icon-button" title="Open bundled examples folder" aria-label="Open bundled examples folder" onClick={() => void onOpenFolder(status.directory)}><FolderOpen size={16} /></button>
        </>}
        <button className="button-quiet" disabled={busy} onClick={() => void install()}>{busy ? "Installing…" : status?.automatic_updates ? "Update examples" : "Install examples"}</button>
      </div>
    </div>
    {failure && <ErrorBanner onRetry={() => void install()} retryLabel="Retry install" busy={busy}>{failure}</ErrorBanner>}
  </section>;
}
