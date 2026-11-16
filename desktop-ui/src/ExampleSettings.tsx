import { useEffect, useState } from "react";
import type { components } from "./generated/studio";
import type { StudioApi } from "./api";
import { CopyPathButton } from "./CopyPathButton";

type Status = components["schemas"]["ExamplesStatus"];

export function ExampleSettings({ workspace, api, onSaved, onOpenFolder, onError }: {
  workspace: string; api: StudioApi; onSaved: () => Promise<void>;
  onOpenFolder: (path: string) => Promise<void>; onError: (message: string) => void;
}) {
  const [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => {
    let live = true;
    setStatus(null); setError(""); setMessage("");
    void api.request<Status>("/v1/examples").then((result) => {
      if (live) setStatus(result);
    }).catch((failure) => { if (live) setError(String(failure)); });
    return () => { live = false; };
  }, [api, workspace]);

  async function install() {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await api.request<Status>("/v1/examples/install", "POST", { workspace }, 180000);
      setStatus(result);
      if (!result.error) setMessage(result.bundled_releases
        ? "Examples are up to date in this workspace."
        : "Example Scenarios is ready. This release does not include any examples yet.");
      await onSaved();
    } catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }

  return <section aria-label="Example scenarios">
    <div className="setting-row">
      <div className="setting-copy"><strong>Example scenarios</strong><p>Install published examples into this workspace, including examples you previously removed.</p>
        <p>{status?.automatic_updates
          ? "New bundled examples and versions are added here automatically while the examples project exists."
          : "Use this action to install or update examples in this workspace."}</p>
      </div>
      <button disabled={busy} onClick={() => void install()}>{busy ? "Installing…" : error || status?.error ? "Retry install/update examples" : "Install/update examples"}</button>
    </div>
    {status?.directory && <div className="setting-row"><div className="setting-copy"><strong>Bundled examples folder</strong></div><div className="setting-control">
      <CopyPathButton path={status.directory} label="Copy bundled examples path" onError={onError} />
      <button onClick={() => void onOpenFolder(status.directory)}>Open bundled examples folder</button>
    </div></div>}
    {(error || status?.error) && <p role="alert" className="error-text">{error || status?.error}</p>}
    {message && <p role="status">{message}</p>}
  </section>;
}
