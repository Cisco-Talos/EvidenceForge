import { useState } from "react";
import { Check, CheckCircle2, ChevronDown, Copy, FolderOpen, Plus, RefreshCw, ShieldCheck, TriangleAlert, X, XCircle } from "lucide-react";
import { Dialog, DropdownMenu } from "radix-ui";
import { invoke, isTauri } from "@tauri-apps/api/core";
import type { CatalogItem, DependencyRow, ImportResult, ImportReview, Project, StudioApi, ValidationResult } from "./api";
import { CopyPathButton } from "./CopyPathButton";
import { ValidationPanel } from "./components";
import { scenarioNameError } from "./scenarioName";
import { packSelection } from "./packSelection";

export function DependencyRows({ rows, selection }: { rows: DependencyRow[]; selection?: {
  selected: Set<string>; requiredBy: Map<string, string[]>; busy: boolean;
  onToggle: (key: string, checked: boolean) => void; onAll: () => void; onNone: () => void;
} }) {
  const [copyError, setCopyError] = useState<string | null>(null);
  return <div className={`dependency-rows ${selection ? "selectable-packs" : ""}`}>
    {selection && <div className="pack-selection-heading"><div><button type="button" className="button-quiet" disabled={selection.busy} onClick={selection.onAll} aria-label="Select all packs">Select all</button><button type="button" className="button-quiet" disabled={selection.busy} onClick={selection.onNone} aria-label="Deselect all packs">Deselect all</button></div><small>{selection.selected.size} selected</small></div>}
    {rows.map((row) => {
    const Icon = row.status === "available" ? CheckCircle2 : ["missing", "conflict"].includes(row.status) ? XCircle : row.status === "copy" ? Copy : TriangleAlert;
    const required = selection?.requiredBy.get(row.key) || [];
    return <div key={row.key} className={`dependency-row dependency-${row.status}`}>
      {selection && row.kind === "pack" && <input type="checkbox" className="visible-check" aria-label={`Import ${row.label}`} checked={selection.selected.has(row.key)} disabled={selection.busy || required.length > 0} aria-describedby={required.length ? `required-${row.key}` : undefined} onChange={(event) => selection.onToggle(row.key, event.target.checked)} />}
      <Icon size={16} aria-label={row.status} /><div><strong>{row.label}</strong><small>{row.detail}</small>
        {required.length > 0 && <small className="required-pack-note" id={`required-${row.key}`}>Required by {required.join(", ")}</small>}
        {row.source && <div className="dependency-path path-with-copy"><small className="path-value" title={row.source}>{row.source}</small><CopyPathButton path={row.source} label={`Copy ${row.label} source path`} onError={setCopyError} /></div>}
        {row.source_digest && row.digest && row.source_digest !== row.digest && <details><summary>Digest changes</summary><code>Original: {row.source_digest}<br />Prepared: {row.digest}</code></details>}
      </div><span>{row.status === "available" ? "Ready" : row.status === "copy" ? "Copy" : row.status === "warning" ? "Note" : row.status === "conflict" ? "Conflict" : "Missing"}</span>
    </div>;
  })}{copyError && <p className="field-error" role="alert">{copyError}</p>}</div>;
}

export function ImportDialog({ kind, initialProjectId = "", projects = [], api, creating = false, onCreate, onImported, onClose }: {
  kind: "scenario" | "pack"; initialProjectId?: string; projects?: Project[]; api: StudioApi;
  creating?: boolean; onCreate?: (name: string, projectId: string) => Promise<void>;
  onImported: (item: CatalogItem | null) => Promise<void>; onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [projectId, setProjectId] = useState(initialProjectId);
  const [action, setAction] = useState<"create" | "import">(kind === "scenario" ? "create" : "import");
  const [sourceMode, setSourceMode] = useState<"file" | "workspace">("file");
  const [path, setPath] = useState("");
  const [configurationContext, setConfigurationContext] = useState("");
  const [sources, setSources] = useState<string[]>([]);
  const [documents, setDocuments] = useState<string[] | null>(null);
  const [review, setReview] = useState<ImportReview | null>(null);
  const [packChoices, setPackChoices] = useState<Set<string> | null>(null);
  const [validation, setValidation] = useState<ValidationResult>();
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const busy = working || creating;
  const nameError = kind === "scenario" ? scenarioNameError(name) : null;
  const selection = packSelection(review?.rows || [], packChoices || new Set());
  const selectedPublishers = kind === "pack" ? (review?.publishers || []).filter((publisher) => [...selection.selected].some((key) => key.startsWith(`${publisher}:`))) : review?.publishers || [];

  async function chooseFile() {
    setError(null);
    try {
      const chosen = sourceMode === "workspace"
        ? await invoke<string | null>("choose_bundle_folder")
        : await invoke<string | null>("choose_import_file", { kind });
      if (chosen) { setPath(chosen); setDocuments(null); setPackChoices(null); }
    } catch (failure) { setError(String(failure)); }
  }
  async function chooseSource(index: number) {
    try {
      const chosen = await invoke<string | null>("choose_bundle_folder");
      if (chosen) editSources(sources.map((source, i) => i === index ? chosen : source));
    } catch (failure) { setError(String(failure)); }
  }
  async function preview() {
    if (nameError || !path.trim()) return;
    setWorking(true); setError(null); setValidation(undefined);
    try {
      if (review) await api.request(`/v1/imports/${review.id}`, "DELETE");
      setReview(null);
      const next = await api.request<ImportReview>(`/v1/imports/${kind}/preview`, "POST", {
        path: path.trim(), source_workspaces: sources.filter((source) => source.trim()).map((source) => source.trim()),
        project_id: projectId || null,
        ...(kind === "scenario" ? { name, documents, ...(configurationContext.trim() ? { configuration_context: configurationContext.trim() } : {}) } : {}),
      }, 180000);
      setReview(next);
      if (kind === "pack") setPackChoices((current) => current === null ? new Set(next.rows.filter((row) => row.kind === "pack").map((row) => row.key)) : new Set([...current].filter((key) => next.rows.some((row) => row.key === key))));
      if (documents === null) setDocuments(next.documents || []);
    } catch (failure) { setError(String(failure)); }
    finally { setWorking(false); }
  }
  async function validate() {
    if (!review) return;
    setWorking(true); setError(null);
    try { setValidation(await api.request<ValidationResult>(`/v1/imports/${review.id}/validate`, "POST", undefined, 190000)); }
    catch (failure) { setError(String(failure)); }
    finally { setWorking(false); }
  }
  async function commit() {
    if (!review || nameError || kind === "pack" && selection.blocked) return;
    setWorking(true); setError(null);
    try {
      const result = await api.request<ImportResult>(`/v1/imports/${review.id}/commit`, "POST", {
        accepted_publishers: selectedPublishers,
        ...(kind === "pack" ? { selected_packs: [...selection.selected] } : {}),
      }, 180000);
      await onImported(result.item || null);
    } catch (failure) { setError(String(failure)); }
    finally { setWorking(false); }
  }
  async function close() {
    if (busy) return;
    if (review) {
      try { await api.request(`/v1/imports/${review.id}`, "DELETE"); }
      catch { /* Expired reviews are also removed by the service. */ }
    }
    onClose();
  }
  function editSources(next: string[]) {
    setSources(next);
    setValidation(undefined);
    if (review) { void api.request(`/v1/imports/${review.id}`, "DELETE").catch(() => undefined); setReview(null); }
  }
  return <Dialog.Root open onOpenChange={(open) => { if (!open) void close(); }}><Dialog.Portal>
    <Dialog.Overlay className="modal-backdrop" />
    <Dialog.Content className={`close-modal import-dialog ${review ? "import-review-dialog" : ""}`} aria-label={kind === "scenario" ? "New scenario" : "Import packs"} onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }} onPointerDownOutside={(event) => event.preventDefault()}>
      <form onSubmit={(event) => { event.preventDefault(); if (review) void commit(); else if (action === "create" && !nameError) void onCreate?.(name, projectId); else void preview(); }}>
        <Dialog.Title>{review ? "Review import" : kind === "scenario" ? "New scenario" : "Import packs"}</Dialog.Title>
        <Dialog.Description>{review ? "Review the copies and dependency actions before importing. Original files stay in place." : action === "create" ? "Name this scenario now. It will appear in the library while you author it." : kind === "pack" ? "Choose a pack release or source workspace to prepare local copies." : "Choose an existing file to prepare a copy in this workspace."}</Dialog.Description>
        {!review && <>
          {kind === "scenario" && <><label className="modal-field">Scenario Name<input name="scenario-name" autoComplete="off" maxLength={80} aria-label="Scenario Name" value={name} disabled={busy} aria-invalid={!!name && !!nameError} aria-describedby={name && nameError ? "new-scenario-name-error" : undefined} onChange={(event) => setName(event.target.value)} /></label>{name && nameError && <p className="field-error" id="new-scenario-name-error" role="status">{nameError}</p>}<label className="modal-field">Project<select aria-label="Project for new scenario" value={projectId} disabled={busy} onChange={(event) => setProjectId(event.target.value)}><option value="">Ungrouped</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label></>}
          {action === "import" && <>
            {kind === "pack" && <label className="modal-field">Project<select aria-label="Project for imported packs" value={projectId} disabled={busy} onChange={(event) => setProjectId(event.target.value)}><option value="">Ungrouped</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>}
            {kind === "pack" && <label className="modal-field">Import from<select aria-label="Pack import source" value={sourceMode} disabled={busy} onChange={(event) => { setSourceMode(event.target.value as "file" | "workspace"); setPath(""); setPackChoices(null); }}><option value="file">Pack release (.efpack)</option><option value="workspace">Source workspace</option></select></label>}
            <label className="modal-field">{sourceMode === "workspace" ? "Source workspace" : kind === "scenario" ? "Scenario YAML" : "Pack release"}<div className="import-path-field"><input aria-label={sourceMode === "workspace" ? "Source workspace" : kind === "scenario" ? "Scenario YAML" : "Pack release"} name="import-source-path" autoComplete="off" value={path} disabled={busy} placeholder={kind === "scenario" ? "/path/to/scenario.yaml" : sourceMode === "workspace" ? "/path/to/workspace" : "/path/to/release.efpack"} onChange={(event) => { setPath(event.target.value); setDocuments(null); setPackChoices(null); }} />{isTauri() && <button type="button" className="button-quiet" disabled={busy} onClick={() => void chooseFile()}><FolderOpen size={15} /> Browse…</button>}</div></label>
            <p className="muted small">{kind === "scenario" ? "Copies YAML, nested includes, referenced assets, and selected Markdown notes. Packs are checked against this workspace first." : "Imports reviewed exact versions and their locked dependencies into this workspace’s pack library."}</p>
          </>}
        </>}
        {review && <><div className="import-destination"><span>Destination</span><div className="path-with-copy"><code className="path-value" title={review.destination}>{review.destination}</code><CopyPathButton path={review.destination} label="Copy import destination" onError={setError} /></div></div>
          <DependencyRows rows={review.rows} selection={kind === "pack" ? {
            ...selection, busy,
            onToggle: (key, checked) => setPackChoices((current) => { const next = new Set(current || []); if (checked) next.add(key); else next.delete(key); return next; }),
            onAll: () => setPackChoices(new Set(review.rows.filter((row) => row.kind === "pack").map((row) => row.key))),
            onNone: () => setPackChoices(new Set()),
          } : undefined} />
          {review.documents && review.documents.length > 0 && <details className="import-documents"><summary>Supporting documents · {(documents || []).length} selected</summary>{review.documents.map((document) => <label key={document}><input className="visible-check" type="checkbox" checked={(documents || []).includes(document)} onChange={(event) => { setDocuments(event.target.checked ? [...(documents || []), document] : (documents || []).filter((entry) => entry !== document)); void api.request(`/v1/imports/${review.id}`, "DELETE").catch(() => undefined); setReview(null); setValidation(undefined); }} />{document}</label>)}</details>}
          {review.publishers && review.publishers.length > 0 && <p className="muted small">Confirming imports these publisher namespaces: {selectedPublishers.join(", ") || "none selected"}.</p>}
          {kind === "scenario" && <div className="import-validation"><button type="button" className="button-quiet" disabled={busy} onClick={() => void validate()}><ShieldCheck size={15} /> {working ? "Working…" : "Validate prepared scenario"}</button><small>Optional sanity check. Findings do not block import.</small>{validation && <ValidationPanel result={validation} />}</div>}
        </>}
        {action === "import" && kind === "scenario" && <details className="import-locations"><summary>Source configuration (optional)</summary><p className="muted small">Select an explicit context file to copy its workspace and ordered overlays into private scenario layers. Review their effect after destination workspace and project configuration. Missing packs are searched in its declared source root.</p><label className="modal-field">Configuration context<div className="import-path-field"><input aria-label="Configuration context" name="configuration-context-file" autoComplete="off" value={configurationContext} disabled={busy} placeholder="/path/to/context.yaml" onChange={(event) => { setConfigurationContext(event.target.value); if (review) { void api.request(`/v1/imports/${review.id}`, "DELETE").catch(() => undefined); setReview(null); setValidation(undefined); } }} />{isTauri() && <button type="button" className="button-quiet" disabled={busy} aria-label="Browse configuration context" onClick={() => void invoke<string | null>("choose_import_file", { kind: "scenario" }).then((chosen) => { if (chosen) { setConfigurationContext(chosen); if (review) { void api.request(`/v1/imports/${review.id}`, "DELETE").catch(() => undefined); setReview(null); setValidation(undefined); } } }).catch((failure) => setError(String(failure)))}><FolderOpen size={15} /> Browse…</button>}</div></label></details>}
        {action === "import" && <details className="import-locations" open={sources.length > 0}><summary>Source workspaces for missing packs</summary><p className="muted small">Add locations to search for exact missing versions. Referenced packs will be copied here.</p>{sources.map((source, index) => <div className="import-path-field" key={index}><input aria-label={`Source workspace ${index + 1}`} name={`source-workspace-${index + 1}`} autoComplete="off" value={source} disabled={busy} onChange={(event) => editSources(sources.map((entry, i) => i === index ? event.target.value : entry))} />{isTauri() && <button type="button" className="icon-button" aria-label={`Browse source workspace ${index + 1}`} disabled={busy} onClick={() => void chooseSource(index)}><FolderOpen size={16} /></button>}<button type="button" className="icon-button" aria-label={`Remove source workspace ${index + 1}`} disabled={busy} onClick={() => editSources(sources.filter((_, i) => i !== index))}><X size={14} /></button></div>)}<button type="button" className="button-quiet" disabled={busy} onClick={() => editSources([...sources, ""])}><Plus size={14} /> Add source workspace</button></details>}
        {error && <p className="field-error" role="alert">{error}</p>}
        <div className="close-modal-actions"><button type="button" className="button-quiet" disabled={busy} onClick={() => void close()}>Cancel</button>
          {review && <button type="button" className="button-quiet" disabled={busy} onClick={() => void preview()}><RefreshCw size={15} /> Refresh review</button>}
          <div className="scenario-split-button"><button type="submit" className="button-primary" disabled={busy || !!nameError || (action === "import" && (!path.trim() || !!review && (kind === "pack" ? selection.blocked : !review.can_import)))}>{busy ? "Working…" : review ? review.rows.some((row) => row.status === "missing" || row.status === "conflict") && kind === "scenario" ? "Import with dependency errors" : "Confirm import" : action === "create" ? "Create scenario" : kind === "scenario" ? "Import scenario" : "Review packs"}</button>
            {kind === "scenario" && !review && <DropdownMenu.Root><DropdownMenu.Trigger type="button" className="button-primary split-trigger" aria-label="Choose scenario action" disabled={busy}><ChevronDown size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu import-action-menu" align="end" sideOffset={5}><DropdownMenu.RadioGroup value={action} onValueChange={(value) => setAction(value as "create" | "import")}><DropdownMenu.RadioItem value="create"><span>{action === "create" && <Check size={14} />}</span>Create scenario</DropdownMenu.RadioItem><DropdownMenu.RadioItem value="import"><span>{action === "import" && <Check size={14} />}</span>Import scenario</DropdownMenu.RadioItem></DropdownMenu.RadioGroup></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>}
          </div>
        </div>
      </form>
    </Dialog.Content>
  </Dialog.Portal></Dialog.Root>;
}
