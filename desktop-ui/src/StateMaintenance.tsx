import { useState } from "react";
import type { UpgradeStatus } from "./api";

export function StateMaintenance({ status, onRetry, onRestore, onWorkspace, requestError }: {
  status: UpgradeStatus;
  onRetry: () => void;
  onRestore: () => void;
  onWorkspace: (path: string) => void;
  requestError?: string | null;
}) {
  const [path, setPath] = useState("");
  const busy = status.state === "running";
  const awaitingAcceptance = status.state === "pending" && !status.error;
  return <div className="boot-screen state-maintenance">
    <img className="boot-logo" src="/brand/evidenceforge-dark.png" alt="EvidenceForge" />
    <h1>{awaitingAcceptance ? "Studio update required" : status.state === "restored" ? "Previous UI state restored" : status.state === "blocked" || status.state === "failed" ? "Studio needs attention" : "Preparing Studio"}</h1>
    {status.warning && <p role="alert" className="upgrade-warning">{status.warning}</p>}
    <p role="status">{status.phase}{busy && status.completed_steps > 0 ? ` · Step ${status.completed_steps} of ${status.total_steps}` : ""}</p>
    {status.error && <p role="alert" className="error-text">{status.error}</p>}
    {requestError && <p role="alert" className="error-text">{requestError}</p>}
    {awaitingAcceptance && <p>Review the upgrade details, then continue to create a verified recovery backup and upgrade your UI state.</p>}
    {status.state === "restored" && <p>Close Studio to use the compatible previous application, or retry the upgrade. Restoration does not install an older application.</p>}
    {!busy && <div className="close-modal-actions">
      {awaitingAcceptance && <button className="button-primary" onClick={onRetry}>Continue with upgrade</button>}
      {!awaitingAcceptance && status.can_retry && <button onClick={onRetry}>Retry upgrade</button>}
      {status.can_restore && <button onClick={() => { if (window.confirm("Restore the UI state saved before this failed upgrade?")) onRestore(); }}>Restore previous UI state</button>}
    </div>}
    <details><summary>View details</summary><p>Operation: {status.operation_id}</p><p>Scope: {status.scope}</p>{status.backup_path && <p>Recovery backup: {status.backup_path}</p>}<pre>{JSON.stringify({ saved: status.versions, target: status.target_versions }, null, 2)}</pre></details>
    {status.scope === "workspace" && !busy && <form onSubmit={(event) => { event.preventDefault(); onWorkspace(path); }}><label>Choose another workspace<input aria-label="Another workspace path" value={path} onChange={(event) => setPath(event.target.value)} /></label><button disabled={!path.trim()}>Open workspace</button></form>}
  </div>;
}
