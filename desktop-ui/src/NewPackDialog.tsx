import { useEffect, useState } from "react";
import { Dialog } from "radix-ui";
import { Sparkles } from "lucide-react";
import type { PackCreation, PackPublisherStatus, Project, StudioApi } from "./api";
import { packNameError } from "./packName";
import { DisplayNameField } from "./DisplayNameField";

export function NewPackDialog({ kind, initialProjectId, projects, api, onCreated, onClose }: {
  kind: "industry_pack" | "organization_pack"; initialProjectId: string; projects: Project[]; api: StudioApi;
  onCreated: (created: PackCreation, details: string) => Promise<void>; onClose: () => void;
}) {
  const [packKind, setPackKind] = useState(kind);
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [details, setDetails] = useState("");
  const [projectId, setProjectId] = useState(initialProjectId);
  const [publisher, setPublisher] = useState<PackPublisherStatus | null>(null);
  const [publisherId, setPublisherId] = useState("");
  const [author, setAuthor] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nameError = packNameError(name);
  useEffect(() => {
    let cancelled = false;
    api.request<PackPublisherStatus>("/v1/packs/publisher").then((value) => { if (!cancelled) setPublisher(value); }).catch((failure) => { if (!cancelled) setError(String(failure)); });
    return () => { cancelled = true; };
  }, [api]);
  const publisherReady = !publisherId && !author.trim() || /^[a-z0-9][a-z0-9-]*$/.test(publisherId) && !!author.trim();
  const ready = !nameError && !!description.trim() && publisherReady;

  async function create() {
    if (!ready || busy) return;
    setBusy(true); setError(null);
    try {
      const created = await api.request<PackCreation>("/v1/packs", "POST", {
        kind: packKind, name, ...(displayName.trim() ? { display_name: displayName.trim() } : {}), description: description.trim(), project_id: projectId || null,
        ...(!publisher?.configured && publisherId ? { publisher: publisherId, publisher_display_name: author.trim() } : {}),
      }, 190000);
      await onCreated(created, details.trim());
    } catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }

  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}><Dialog.Portal>
    <Dialog.Overlay className="modal-backdrop" />
    <Dialog.Content className="close-modal new-pack-dialog" aria-label="New pack" onPointerDownOutside={(event) => event.preventDefault()} onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }}>
      <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
        <Dialog.Title>New pack</Dialog.Title>
        <Dialog.Description>Create a named draft, then shape it in a conversation.</Dialog.Description>
        <div className="pack-form-pair"><label className="modal-field">Pack type<select aria-label="New pack type" value={packKind} disabled={busy} onChange={(event) => setPackKind(event.target.value as typeof packKind)}><option value="industry_pack">Industry</option><option value="organization_pack">Organization</option></select></label>
          <label className="modal-field">Project<select aria-label="Project for new pack" value={projectId} disabled={busy} onChange={(event) => setProjectId(event.target.value)}><option value="">Ungrouped</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label></div>
        <label className="modal-field">Pack Name<input autoFocus name="pack-name" autoComplete="off" aria-label="Pack Name" aria-invalid={!!name && !!nameError} aria-describedby={name && nameError ? "new-pack-name-error" : "pack-name-help"} disabled={busy} value={name} onChange={(event) => setName(event.target.value)} /></label>
        {name && nameError ? <p className="field-error" id="new-pack-name-error" role="status">{nameError}</p> : <p className="muted small" id="pack-name-help">Lowercase letters, digits, and hyphens. Starts as a draft; choose its version when publishing.</p>}
        <DisplayNameField label="Pack display name" value={displayName} onChange={setDisplayName} disabled={busy} placeholder="For example, Northstar Health" api={api} source={nameError ? null : { context: { kind: packKind, name, description, details } }} />
        <label className="modal-field">Description<textarea aria-label="Pack description" rows={2} maxLength={2000} disabled={busy} value={description} onChange={(event) => setDescription(event.target.value)} /></label>
        {publisher?.configured ? <p className="pack-author-info">Author <strong>{publisher.publisher_display_name}</strong><small>{publisher.publisher}</small></p> : publisher ? <div className="pack-publisher-fields"><p className="muted small">Publisher is optional while drafting and required at publication. If supplied, it is remembered for this workspace.</p><div className="pack-form-pair"><label className="modal-field">Publisher ID<input aria-label="Publisher ID" name="pack-publisher-id" autoComplete="off" disabled={busy} value={publisherId} onChange={(event) => setPublisherId(event.target.value)} /></label><label className="modal-field">Author display name<input aria-label="Author display name" name="pack-author-display-name" autoComplete="off" maxLength={120} disabled={busy} value={author} onChange={(event) => setAuthor(event.target.value)} /></label></div>{publisherId && !/^[a-z0-9][a-z0-9-]*$/.test(publisherId) && <p className="field-error" role="status">Publisher ID uses lowercase letters, digits, and hyphens.</p>}</div> : <p className="muted small">Checking author identity…</p>}
        <label className="modal-field"><span>Details <span className="muted">· optional</span></span><textarea aria-label="Pack details" rows={3} maxLength={16000} disabled={busy} placeholder="Describe what you'd like this pack to contain…" value={details} onChange={(event) => setDetails(event.target.value)} /></label>
        <p className="muted small">Details are sent as the first chat message when you create the pack. Leave them empty to start the conversation yourself.</p>
        {error && <p className="field-error" role="alert">{error}</p>}
        <div className="close-modal-actions"><button type="button" className="button-quiet" disabled={busy} onClick={onClose}>Cancel</button><button className="button-primary" type="submit" disabled={busy || !ready}><Sparkles size={16} aria-hidden="true" />{busy ? "Creating…" : "Create pack"}</button></div>
      </form>
    </Dialog.Content>
  </Dialog.Portal></Dialog.Root>;
}
