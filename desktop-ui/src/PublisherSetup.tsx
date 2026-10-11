import { useId, useState } from "react";
import type { FormEvent } from "react";
import type { PackPublisherStatus, StudioApi } from "./api";

export function PublisherSetup({ status, workspace, api, onSaved, notice = false, hidden = false }: {
  status?: PackPublisherStatus | null;
  workspace: string;
  api: StudioApi;
  onSaved: () => Promise<void>;
  notice?: boolean;
  hidden?: boolean;
}) {
  const id = useId();
  const [expanded, setExpanded] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [publisher, setPublisher] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [scope, setScope] = useState<"user" | "project">("user");
  const [editing, setEditing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [review, setReview] = useState<PackPublisherStatus | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function edit(targetScope: "user" | "project") {
    setEditing(true); setScope(targetScope); setLoading(true); setReview(null); setError("");
    try {
      const current = await api.request<PackPublisherStatus>(`/v1/packs/publisher?scope=${targetScope}`);
      setReview(current);
      setPublisher(current.publisher || status?.publisher || "");
      setDisplayName(current.publisher_display_name || status?.publisher_display_name || "");
    } catch (failure) { setError(String(failure)); }
    finally { setLoading(false); }
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true); setError("");
    try {
      await api.request<PackPublisherStatus>("/v1/packs/publisher", "POST", {
        publisher: publisher.trim(), publisher_display_name: displayName.trim(), scope, workspace,
        ...(editing ? { replace: true, expected_identity: review?.configured ? {
          publisher: review.publisher, publisher_display_name: review.publisher_display_name,
        } : null } : {}),
      });
      await onSaved();
      setEditing(false); setReview(null); setPublisher(""); setDisplayName(""); setScope("user");
    } catch (failure) { setError(String(failure)); }
    finally { setSaving(false); }
  }

  if (hidden || (notice && (!status || status.configured || dismissed))) return null;
  return <section className={`publisher-setup ${notice ? "publisher-setup-notice" : "publisher-setup-settings"}`} aria-label="Publisher setup">
    <div className="publisher-setup-heading">
      <div><strong>Publisher identity</strong><p>{status?.configured
        ? `${status.publisher_display_name} · ${status.publisher} · ${status.scope === "user" ? "Global" : "This workspace"}`
        : "Choose the name attached to your scenario and pack releases. You can keep working without it."}</p></div>
      {notice && !expanded && !status?.error && <button type="button" className="button-quiet" onClick={() => setExpanded(true)}>Set up publisher</button>}
      {notice && <button type="button" className="button-quiet" disabled={saving} onClick={() => setDismissed(true)}>Later</button>}
      {!notice && status?.configured && !editing && <button type="button" className="button-quiet" onClick={() => void edit(status.scope || "user")}>Edit publisher</button>}
    </div>
    {!status && !notice && <p role="status">Publisher status is unavailable. Reconnect Studio to check setup.</p>}
    {status?.error && <p className="error-text" role="alert">{status.error}</p>}
    {status && (editing || !status.configured) && !status.error && (!notice || expanded) && <form onSubmit={(event) => void save(event)}>
      {loading && <p role="status">Reading publisher settings…</p>}
      <div className="publisher-setup-fields">
        <label className="modal-field" htmlFor={`${id}-publisher`}>Publisher ID<input id={`${id}-publisher`} required pattern="[a-z0-9][a-z0-9-]*" autoComplete="off" disabled={saving || loading} value={publisher} onChange={(event) => setPublisher(event.target.value)} placeholder="e.g. cedar-grove" aria-describedby={`${id}-help`} /></label>
        <label className="modal-field" htmlFor={`${id}-name`}>Display name<input id={`${id}-name`} required maxLength={120} autoComplete="off" disabled={saving || loading} value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="e.g. Cedar Grove" /></label>
        <label className="modal-field" htmlFor={`${id}-scope`}>Save for<select id={`${id}-scope`} disabled={saving || loading} value={scope} onChange={(event) => { const selected = event.target.value as "user" | "project"; if (editing) void edit(selected); else setScope(selected); }}><option value="user">Global</option><option value="project">This workspace</option></select></label>
      </div>
      <p id={`${id}-help`} className="muted small">Use lowercase letters, numbers and hyphens for the ID. Global is shared by Studio and the CLI across your workspaces. A workspace identity takes precedence. This is a release namespace, not verified authorship.</p>
      {editing && <p className="muted small">Updates the default for new artifacts and drafts without a publisher. Drafts with an explicit publisher and published releases keep their recorded identity.</p>}
      {editing && scope === "user" && status.scope === "project" && <p className="muted small">This workspace has its own publisher, which will continue to override Global here.</p>}
      {error && <p className="error-text" role="alert">{error}</p>}
      <div className="job-actions"><button type="submit" className="button-primary" disabled={saving || loading || (editing && (!review || (review.publisher === publisher.trim() && review.publisher_display_name === displayName.trim()))) || !/^[a-z0-9][a-z0-9-]*$/.test(publisher.trim()) || !displayName.trim()}>{saving ? "Saving…" : editing ? "Save changes" : "Save publisher"}</button>{editing && <button type="button" className="button-quiet" disabled={saving || loading} onClick={() => { setEditing(false); setReview(null); setError(""); setPublisher(""); setDisplayName(""); setScope("user"); }}>Cancel</button>}{editing && error && <button type="button" className="button-quiet" disabled={saving || loading} onClick={() => void edit(scope)}>Refresh edit</button>}</div>
    </form>}
  </section>;
}
