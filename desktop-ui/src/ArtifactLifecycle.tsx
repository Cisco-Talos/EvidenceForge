import { artifactFilename } from "./artifactNaming";
import { useEffect, useState } from "react";
import { Download, GitBranch, Upload } from "lucide-react";
import { Dialog } from "radix-ui";
import type { CatalogItem, StudioApi } from "./api";
import type { components } from "./generated/studio";

type Info = components["schemas"]["ArtifactInfo"];

export function ArtifactLifecycle({ item, api, onChanged, onOpen, compact = true, disabled = false, onProperties }: {
  item: CatalogItem; api: StudioApi; onChanged: () => Promise<void>;
  onOpen?: (path: string) => Promise<void>; compact?: boolean; disabled?: boolean; onProperties?: () => void;
}) {
  const [info, setInfo] = useState<Info | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [version, setVersion] = useState("");
  const [publishing, setPublishing] = useState(false);
  const [publicationReview, setPublicationReview] = useState<Info | null>(null);
  const [warnings, setWarnings] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [findings, setFindings] = useState<{severity?: string; message?: string}[]>([]);
  useEffect(() => {
    let live = true;
    api.request<Info>(`/v1/items/${item.id}/lifecycle`).then((value) => {
      if (live) { setInfo(value); setError(""); }
    }).catch((failure) => { if (live) setError(String(failure)); });
    return () => { live = false; };
  }, [api, item.id, item.source_sha256, refresh]);
  async function reviewPublication(resetVersion: boolean) {
    setPublishing(true); setPublicationReview(null); setBusy(true); setError(""); setWarnings(false);
    try {
      const current = await api.request<Info>(`/v1/items/${item.id}/lifecycle`);
      if (current.lifecycle?.status !== "draft") throw new Error("This source is no longer a draft. Refresh the workspace.");
      setInfo(current); setPublicationReview(current);
      if (resetVersion) setVersion(current.suggested_version || "");
    } catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }
  async function action(operation: "draft" | "upgrade" | "publish" | "recover") {
    if (operation === "publish" && !publicationReview) return;
    setBusy(true); setError("");
    try {
      const result = await api.request<{ path: string; findings?: {severity?: string; message?: string}[] }>(`/v1/items/${item.id}/lifecycle`, "POST", {
        action: operation, expected_digest: operation === "publish" ? publicationReview?.digest : info?.digest, ...(operation === "publish" ? { version: version || null, accept_warnings: warnings } : {}),
      }, 180000);
      setFindings(result.findings || []); setPublishing(false); await onChanged(); setRefresh((value) => value + 1);
      await onOpen?.(result.path);
    } catch (failure) {
      const message = String(failure);
      setError(message);
      if (operation === "publish" && message.includes("source changed after review")) setPublicationReview(null);
    }
    finally { setBusy(false); }
  }
  async function exportRelease() {
    setBusy(true); setError("");
    try { await api.download(`/v1/items/${item.id}/release`, artifactFilename(item, item.kind === "scenario" ? "efscenario" : "efpack")); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }
  const metadata = info?.lifecycle;
  return <section className={`artifact-lifecycle ${compact ? "artifact-version-bar" : "surface"}`} aria-label="Versions and publication">
    <header>{!compact && <h2>Versions & publication</h2>}<span>{metadata?.status === "published" ? `Published ${metadata.version}` : metadata?.status === "draft" ? "Draft" : "Legacy source"}</span></header>
    {error && !publishing && <p className="error-text" role="alert">{error}</p>}
    {!!findings.length && <div role="status"><p>Upgrade validation findings</p><ul>{findings.map((finding, index) => <li key={index}>{finding.severity}: {finding.message}</li>)}</ul></div>}
    <div className="job-actions">
      {metadata?.status !== "draft" && <button className="button-quiet" disabled={busy || disabled} onClick={() => void action("draft")}><GitBranch size={15} />New draft</button>}
      {info?.upgrade_available && <button className="button-quiet" disabled={busy || disabled} onClick={() => void action("upgrade")}>Upgrade to latest schema</button>}
      {metadata?.status === "published" && <button className="button-quiet" disabled={busy || disabled} onClick={() => void exportRelease()}><Download size={15} />Export release…</button>}
      {metadata?.status === "draft" && <button className="button-primary" disabled={busy || disabled} onClick={() => void reviewPublication(true)}><Upload size={15} />Publish locally…</button>}
      {error.includes("modified") && <button className="button-quiet" disabled={busy || disabled} onClick={() => void action("recover")}>Recover into draft</button>}
    </div>
    {onProperties && <button className="button-quiet" onClick={onProperties}>Versions…</button>}
    <Dialog.Root open={publishing} onOpenChange={(open) => { if (!busy) setPublishing(open); }}><Dialog.Portal><Dialog.Overlay className="radix-dialog-overlay" /><Dialog.Content className="environment-picker" onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }} onPointerDownOutside={(event) => event.preventDefault()}><Dialog.Title>Publish local release</Dialog.Title><Dialog.Description>Publication validates and freezes this draft. Export is a separate action.</Dialog.Description>{busy && !publicationReview && <p role="status">Reading the current draft…</p>}<label>Release version<input disabled={busy || disabled} value={version} onChange={(event) => setVersion(event.target.value)} placeholder="Suggest next unused patch" pattern="\d+\.\d+\.\d+" /></label>{error.includes("review publication warnings") && <label><input type="checkbox" checked={warnings} onChange={(event) => setWarnings(event.target.checked)} />I have reviewed the reported validation warnings</label>}{error && <p className="error-text" role="alert">{error}</p>}<footer><Dialog.Close className="button-quiet" disabled={busy || disabled}>Cancel</Dialog.Close><button className="button-quiet" disabled={busy || disabled} onClick={() => void reviewPublication(false)}>Refresh review</button><button className="button-primary" disabled={busy || !publicationReview} onClick={() => void action("publish")}>{busy ? publicationReview ? "Publishing…" : "Reviewing…" : "Publish locally"}</button></footer></Dialog.Content></Dialog.Portal></Dialog.Root>
  </section>;
}
