import { artifactFilename } from "./artifactNaming";
import { useEffect, useId, useState, type ReactNode } from "react";
import { Dialog } from "radix-ui";
import { ActionShortcut, ObjectMenu, type ObjectAction } from "./ObjectActions";
import { StudioApiError, type CatalogItem, type StudioApi } from "./api";
import type { components } from "./generated/studio";

type Finding = { severity?: string; field_path?: string; message?: string };

type Info = components["schemas"]["ArtifactInfo"];

export function ArtifactLifecycle({ item, api, onChanged, onOpen, compact = true, disabled = false, starter = false, onProperties, inspect = true, renderActions, onError }: {
  item: CatalogItem; api: StudioApi; onChanged: () => Promise<void>;
  onOpen?: (path: string) => Promise<void>; compact?: boolean; disabled?: boolean; starter?: boolean; onProperties?: () => void; inspect?: boolean; renderActions?: (actions: ObjectAction[]) => ReactNode; onError?: (message: string) => void;
}) {
  const versionId = useId();
  const [info, setInfo] = useState<Info | null>(null);
  const [busy, setBusy] = useState(false);
  const [inspectionError, setInspectionError] = useState("");
  const [actionError, setActionError] = useState("");
  const [publicationError, setPublicationError] = useState("");
  const [publicationIssues, setPublicationIssues] = useState<Finding[]>([]);
  const [version, setVersion] = useState("");
  const [publishing, setPublishing] = useState(false);
  const [publicationReview, setPublicationReview] = useState<Info | null>(null);
  const [warnings, setWarnings] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  useEffect(() => {
    setInfo(null); setInspectionError(""); setActionError(""); setFindings([]); closePublication();
  }, [item.id]);
  useEffect(() => {
    if (!inspect) return;
    let live = true;
    api.request<Info>(`/v1/items/${item.id}/lifecycle`).then((value) => {
      if (live) { setInfo(value); setInspectionError(""); }
    }).catch((failure) => { if (live) setInspectionError(String(failure)); });
    return () => { live = false; };
  }, [api, item.id, item.source_sha256, refresh, inspect]);
  async function reviewPublication(resetVersion: boolean) {
    setPublishing(true); setPublicationReview(null); setBusy(true); setPublicationError(""); setPublicationIssues([]); setWarnings(false);
    try {
      const current = await api.request<Info>(`/v1/items/${item.id}/lifecycle`);
      if (current.lifecycle?.status !== "draft") throw new Error("This source is no longer a draft. Refresh the workspace.");
      setInfo(current);
      if (current.starter_draft) throw new Error("Ready to author — continue the conversation to build this scenario.");
      setPublicationReview(current);
      if (resetVersion) setVersion(current.suggested_version || "1.0.0");
    } catch (failure) { setPublicationError(String(failure)); }
    finally { setBusy(false); }
  }
  function closePublication() {
    setPublishing(false); setPublicationReview(null); setPublicationError(""); setPublicationIssues([]); setWarnings(false);
  }
  async function action(operation: "draft" | "upgrade" | "publish" | "recover") {
    if (operation === "publish" && !publicationReview) return;
    setBusy(true); setActionError("");
    if (operation === "publish") { setPublicationError(""); setPublicationIssues([]); }
    try {
      const result = await api.request<{ path: string; findings?: Finding[] }>(`/v1/items/${item.id}/lifecycle`, "POST", {
        action: operation, expected_digest: operation === "publish" ? publicationReview?.digest : info?.digest, ...(operation === "publish" ? { version: version || null, accept_warnings: warnings } : {}),
      }, 180000);
      setFindings(result.findings || []); closePublication(); await onChanged(); setRefresh((value) => value + 1);
      await onOpen?.(result.path);
    } catch (failure) {
      const message = String(failure);
      if (operation === "publish") {
        setPublicationError(message);
        if (failure instanceof StudioApiError && failure.detail && typeof failure.detail === "object" && "issues" in failure.detail && Array.isArray(failure.detail.issues)) {
          setPublicationIssues(failure.detail.issues.filter((issue): issue is Finding => !!issue && typeof issue === "object" && typeof issue.message === "string"));
        }
      } else { setActionError(message); onError?.(message); }
      if (operation === "publish" && message.includes("source changed after review")) setPublicationReview(null);
    }
    finally { setBusy(false); }
  }
  async function exportRelease() {
    setBusy(true); setActionError("");
    try { await api.download(`/v1/items/${item.id}/release`, artifactFilename(item, item.kind === "scenario" ? "efscenario" : "efpack")); }
    catch (failure) { setActionError(String(failure)); onError?.(String(failure)); }
    finally { setBusy(false); }
  }
  const metadata = info?.lifecycle;
  const error = inspectionError || actionError;
  const awaitingAuthoring = starter || info?.starter_draft;
  const unavailable = busy || disabled || !info;
  const statusReason = busy ? "An artifact operation is in progress" : disabled ? "Finish the active operation first" : !info ? error || "Reading artifact status" : undefined;
  const lifecycleActions: ObjectAction[] = [
    ...(onProperties ? [{ id: "versions", label: "Versions", group: "inspect" as const, run: onProperties }] : []),
    { id: "publish", label: "Publish locally…", group: "work", disabled: unavailable || metadata?.status !== "draft" || !!awaitingAuthoring, reason: statusReason || (awaitingAuthoring ? "Continue authoring before publication" : "Create a draft before publication"), run: () => reviewPublication(true) },
    { id: "upgrade", label: "Upgrade to latest schema", group: "work", disabled: unavailable || !info?.upgrade_available, reason: statusReason || "This artifact already uses the latest supported schema", run: () => action("upgrade") },
    { id: "draft", label: "New draft", group: "reuse", disabled: unavailable || metadata?.status === "draft", reason: statusReason || "This artifact is already a draft", run: () => action("draft") },
    { id: "recover", label: "Recover into draft", group: "reuse", disabled: busy || disabled || !error.includes("modified"), reason: busy || disabled ? statusReason : "Recovery applies to a modified immutable release", run: () => action("recover") },
    { id: "export-release", label: "Export release…", group: "reuse", disabled: unavailable || metadata?.status !== "published", reason: statusReason || "Publish this draft before exporting its release", run: exportRelease },
  ];
  const publicationDialog = <Dialog.Root open={publishing} onOpenChange={(open) => { if (!busy) { if (open) setPublishing(true); else closePublication(); } }}><Dialog.Portal><Dialog.Overlay className="radix-dialog-overlay" /><Dialog.Content className="environment-picker" onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }} onPointerDownOutside={(event) => event.preventDefault()}><Dialog.Title>Publish local release</Dialog.Title><Dialog.Description>Publication validates this draft and replaces it in the library with a read-only release. Create a new draft from the release to revise it. Export is a separate action.</Dialog.Description>{busy && !publicationReview && <p role="status">Reading the current draft…</p>}<div className="modal-field publication-version-field">
      <label htmlFor={versionId}>Release version</label>
      <input id={versionId} disabled={busy || disabled} value={version} onChange={(event) => setVersion(event.target.value)} placeholder="X.Y.Z" pattern="\d+\.\d+\.\d+" aria-describedby={`${versionId}-help`} />
      <span id={`${versionId}-help`} className="muted small">Defaults to the next unused patch version, starting at 1.0.0. You can edit it before publishing.</span>
    </div>{publicationError.includes("review publication warnings") && <label><input type="checkbox" checked={warnings} onChange={(event) => setWarnings(event.target.checked)} />I have reviewed the reported validation warnings</label>}{publicationError && <div className="error-text" role="alert"><p>{publicationError.includes("publisher identity is required") ? "Set up your publisher identity in Settings → Workspace, then reopen publication to review the suggested version." : publicationError}</p>{!!publicationIssues.length && <ul>{publicationIssues.map((issue, index) => <li key={index}><strong>{issue.field_path || "Scenario"}</strong>: {issue.message}</li>)}</ul>}</div>}<footer><Dialog.Close className="button-quiet" disabled={busy || disabled}>Cancel</Dialog.Close><button className="button-quiet" disabled={busy || disabled} onClick={() => void reviewPublication(false)}>Refresh review</button><button className="button-primary" disabled={busy || disabled || awaitingAuthoring || !publicationReview} onClick={() => void action("publish")}>{busy ? publicationReview ? "Publishing…" : "Reviewing…" : "Publish locally"}</button></footer></Dialog.Content></Dialog.Portal></Dialog.Root>;
  if (renderActions) return <>{renderActions(lifecycleActions)}{publicationDialog}</>;
  return <section className={`artifact-lifecycle ${compact ? "artifact-version-bar" : "surface"}`} aria-label="Versions and publication">
    <header>{!compact && <h2>Versions & publication</h2>}<span>{metadata?.status === "published" ? `Published ${metadata.version}` : metadata?.status === "draft" ? "Draft" : "Legacy source"}</span></header>
    {error && <p className="error-text" role="alert">{error}</p>}
    {!!findings.length && <div role="status"><p>Upgrade validation findings</p><ul>{findings.map((finding, index) => <li key={index}>{finding.severity}: {finding.message}</li>)}</ul></div>}
    <div className="job-actions"><ActionShortcut action={lifecycleActions.find((entry) => entry.id === (metadata?.status === "draft" ? "publish" : "draft"))!} primary={metadata?.status === "draft"} /><ObjectMenu label="Versions and publication actions" actions={lifecycleActions} /></div>
    {publicationDialog}
  </section>;
}
