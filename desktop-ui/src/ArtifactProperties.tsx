import { useEffect, useRef, useState, type ReactNode } from "react";
import { Dialog } from "radix-ui";
import { FileText, GitBranch, Info, Layers3, LoaderCircle, Pencil, Sparkles, X } from "lucide-react";
import type { CatalogItem, StudioApi, StudioSnapshot } from "./api";
import type { components } from "./generated/studio";
import { artifactTitle, suggestedIdentifier, artifactNameError } from "./artifactNaming";
import { ArtifactLifecycle } from "./ArtifactLifecycle";
import { DisplayNameField } from "./DisplayNameField";
import { ReleaseNotesField } from "./ReleaseNotesField";
import { Help, formatBundleSize } from "./components";

export type PropertiesSection = "general" | "versions" | "dependencies" | "technical";
type Properties = components["schemas"]["ArtifactProperties"];
type BundleInfo = components["schemas"]["BundleProperties"];
type Info = components["schemas"]["ArtifactInfo"];
const tabs = [{ id: "general", label: "General", icon: FileText }, { id: "versions", label: "Versions & publication", icon: GitBranch }, { id: "dependencies", label: "Dependencies", icon: Layers3 }, { id: "technical", label: "Technical details", icon: Info }] as const;

function logTypeLabel(format: string): string {
  if (format === "windows") return "Windows (Security & Sysmon)";
  if (format === "windows_event_security") return "Windows Security events";
  if (format === "windows_event_sysmon" || format === "sysmon") return "Sysmon";
  if (format === "ecar") return "EDR (eCAR)";
  if (format === "zeek") return "Zeek";
  if (format.startsWith("zeek_")) return `Zeek · ${format.slice(5).replace(/_/g, " ")}`;
  return format.replace(/_/g, " ");
}

function PropertiesShell({ title, section, onSection, onClose, children, footer, dirty = false, busy = false, bundle = false }: {
  title: string; section: PropertiesSection; onSection: (section: PropertiesSection) => void;
  onClose: () => void; children: ReactNode; footer?: ReactNode; dirty?: boolean; busy?: boolean; bundle?: boolean;
}) {
  const [discard, setDiscard] = useState(false);
  function close() { if (busy) return; if (dirty) setDiscard(true); else onClose(); }
  return <Dialog.Root open onOpenChange={(open) => { if (!open) close(); }}><Dialog.Portal><Dialog.Overlay className="radix-dialog-overlay" /><Dialog.Content className="properties-dialog" onPointerDownOutside={(event) => event.preventDefault()} onEscapeKeyDown={(event) => { event.preventDefault(); close(); }}>
    <header className="properties-heading"><div><span className="eyebrow">PROPERTIES</span><Dialog.Title title={title}>{title}</Dialog.Title></div><button className="icon-button" aria-label="Close properties" disabled={busy} onClick={close}><X size={19} /></button></header>
    <Dialog.Description className="sr-only">Inspect this artifact and edit its available draft properties.</Dialog.Description>
    <div className="settings-layout properties-layout"><nav className="settings-nav" aria-label="Properties sections">{tabs.filter((tab) => !bundle || tab.id !== "versions").map((tab) => <button key={tab.id} className={section === tab.id ? "active" : ""} aria-current={section === tab.id ? "page" : undefined} onClick={() => onSection(tab.id)}><tab.icon size={17} /><span>{bundle && tab.id === "dependencies" ? "Captured inputs" : tab.label}</span></button>)}</nav><div className="properties-content">{children}</div></div>
    <footer className="properties-footer">{discard ? <><span>Discard unsaved property changes?</span><button className="button-quiet" onClick={() => setDiscard(false)}>Keep editing</button><button className="button-danger" onClick={onClose}>Discard changes</button></> : <>{footer}<button className="button-quiet" disabled={busy} onClick={close}>Close</button></>}</footer>
  </Dialog.Content></Dialog.Portal></Dialog.Root>;
}

function Property({ label, help, children }: { label: string; help: string; children: ReactNode }) {
  return <div className="property-row"><div className="property-label">{label}<Help text={help} /></div><div className="property-value">{children}</div></div>;
}

function DescriptionField({ value, onChange, api, itemId, digest, disabled }: { value: string; onChange: (value: string) => void; api: StudioApi; itemId: string; digest: string; disabled: boolean }) {
  const [preview, setPreview] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const revision = useRef(0);
  const live = useRef(false);
  const current = useRef({ value, digest }); current.current = { value, digest };
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  useEffect(() => { setPreview(null); }, [digest]);
  async function suggest() {
    const captured = current.current; const edit = revision.current;
    setPending(true); setError(""); setPreview(null);
    const unchanged = () => live.current && current.current.digest === captured.digest && current.current.value === captured.value && revision.current === edit;
    try { const proposed = await api.request<{ description: string }>("/v1/assist/description", "POST", { item_id: itemId, expected_digest: digest }, 130000); if (unchanged()) setPreview(proposed.description); }
    catch (failure) { if (unchanged()) setError(String(failure)); }
    finally { if (live.current) setPending(false); }
  }
  return <div className="modal-field"><div className="assisted-field-heading"><label htmlFor="properties-description">Description</label><Help text="Overview of this artifact. Release notes describe what changed in this version." /><button className="icon-button" type="button" aria-label="Suggest description with AI" title="Suggest description with AI" disabled={disabled || pending} onClick={() => void suggest()}>{pending ? <LoaderCircle size={16} className="spinner" /> : <Sparkles size={16} />}</button></div><textarea id="properties-description" rows={4} maxLength={65536} disabled={disabled} value={value} onChange={(event) => { revision.current++; setPreview(null); onChange(event.target.value); }} />{pending && <p className="muted small" role="status">Suggesting an overview…</p>}{error && <p className="field-error" role="alert">{error}</p>}{preview !== null && <div className="suggestion-preview" role="region" aria-label="AI description preview"><label>Suggested description<textarea rows={4} value={preview} onChange={(event) => setPreview(event.target.value)} /></label><div className="job-actions"><button type="button" className="button-quiet" onClick={() => setPreview(null)}>Dismiss</button><button type="button" className="button-quiet" disabled={disabled || !preview.trim()} onClick={() => { revision.current++; onChange(preview); setPreview(null); }}>Use suggestion</button></div></div>}</div>;
}

export function ArtifactPropertiesDialog({ item, initialSection = "general", snapshot, api, onClose, onChanged, onOpen, onProjectChange }: {
  item: CatalogItem; initialSection?: PropertiesSection; snapshot: StudioSnapshot; api: StudioApi;
  onClose: () => void; onChanged: () => Promise<void>; onOpen: (path: string) => Promise<void>;
  onProjectChange: (id: string | null) => void;
}) {
  const [section, setSection] = useState<PropertiesSection>(initialSection);
  const [properties, setProperties] = useState<Properties | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [history, setHistory] = useState(false);
  const [identity, setIdentity] = useState(false);
  const [identifier, setIdentifier] = useState(item.name);
  const [publisher, setPublisher] = useState(item.publisher);
  const [review, setReview] = useState<Info | null>(null);
  const editable = properties?.lifecycle?.status === "draft";
  const dirty = !!properties && (displayName !== (properties.display_name || "") || description !== properties.description || notes !== (properties.lifecycle?.release_notes || ""));
  useEffect(() => {
    let live = true;
    void api.request<Properties>(`/v1/items/${item.id}/properties`).then((value) => { if (live) { setProperties(value); setDisplayName(value.display_name || ""); setDescription(value.description); setNotes(value.lifecycle?.release_notes || ""); setError(""); } }).catch((failure) => { if (live) setError(String(failure)); });
    return () => { live = false; };
  }, [api, item.id, refresh]);
  async function save() {
    if (!properties) return;
    setBusy(true); setError(""); setStatus("");
    try { await api.request(`/v1/items/${item.id}/properties`, "PATCH", { display_name: displayName.trim() || null, description, release_notes: notes, expected_digest: properties.digest }); await onChanged(); const saved = await api.request<Properties>(`/v1/items/${item.id}/properties`); setProperties(saved); setDisplayName(saved.display_name || ""); setDescription(saved.description); setNotes(saved.lifecycle?.release_notes || ""); setStatus("Properties saved."); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }
  async function newIdentity() {
    if (!properties || !review) return;
    const nameError = artifactNameError(identifier, item.kind === "scenario" ? "scenario" : "pack");
    if (nameError) { setError(nameError); return; }
    if (publisher && !/^[a-z0-9][a-z0-9-]*$/.test(publisher)) { setError("Publisher uses lowercase letters, numbers and hyphens."); return; }
    setBusy(true); setError("");
    try { const result = await api.request<{ path: string }>(`/v1/items/${item.id}/lifecycle`, "POST", { action: "draft", name: identifier, publisher: publisher || null, expected_digest: properties.digest }, 180000); await onChanged(); onClose(); await onOpen(result.path); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }
  async function reviewIdentity() {
    if (!properties || dirty) return;
    setIdentity(true); setReview(null); setIdentifier(properties.name); setPublisher(properties.lifecycle?.publisher || ""); setBusy(true); setError("");
    try { const value = await api.request<Info>(`/v1/items/${item.id}/lifecycle?names=true`); if (value.digest !== properties.digest) throw new Error("Source changed. Refresh Properties before changing identity."); setReview(value); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }
  async function validate() {
    if (!properties) return;
    setBusy(true); setError(""); setStatus("");
    try { const result = await api.request<{ findings: { severity: string; message: string }[] }>(`/v1/items/${item.id}/lifecycle`, "POST", { action: "validate", expected_digest: properties.digest }, 180000); setStatus(result.findings.length ? result.findings.map((finding) => `${finding.severity}: ${finding.message}`).join("\n") : "Validation passed."); setRefresh((value) => value + 1); await onChanged(); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }
  const open = async (path: string) => { onClose(); await onOpen(path); };
  return <PropertiesShell title={artifactTitle(item)} section={section} onSection={setSection} onClose={onClose} dirty={dirty} busy={busy} footer={<>{dirty && <span className="muted small">Unsaved changes</span>}{editable && <button className="button-primary" disabled={busy || !dirty} onClick={() => void save()}>Save properties</button>}</>}>
    {error && <p className="error-text" role="alert">{error}<button className="button-quiet" disabled={busy || dirty} onClick={() => setRefresh((value) => value + 1)}>Refresh properties</button></p>}{status && <p className="property-status" role="status">{status}</p>}
    {!properties ? <p className="muted">Reading properties…</p> : <>
      {section === "general" && <><h2>General</h2>{!editable && <div className="properties-readonly"><span>{properties.lifecycle?.status === "published" ? "Published release · read-only" : "Legacy source · read-only"}</span><ArtifactLifecycle item={item} api={api} onChanged={onChanged} onOpen={open} compact /></div>}
        <DisplayNameField value={displayName} onChange={setDisplayName} label="Display name" placeholder={properties.name} disabled={busy || !editable} api={api} source={{ item_id: item.id, expected_digest: properties.digest }} allowReplacement previewRequired help="Optional friendly title. It does not change the identifier, references or file names." />
        <Property label="Identifier" help="Stable reference name. A different identifier creates a linked draft with a new logical identity."><span className="property-code">{properties.name}</span><button className="icon-button" aria-label="Change identifier" title="Change identifier" disabled={busy || dirty} onClick={() => void reviewIdentity()}><Pencil size={16} /></button></Property>
        <DescriptionField value={description} onChange={setDescription} api={api} itemId={item.id} digest={properties.digest} disabled={busy || !editable} />
        <Property label="Publisher" help="Namespace used for release identity. It is not authenticated authorship. A change creates a linked draft."><span>{properties.lifecycle?.publisher || item.publisher || "Not set"}</span><button className="icon-button" aria-label="Change publisher" title="Change publisher" disabled={busy || dirty} onClick={() => void reviewIdentity()}><Pencil size={16} /></button></Property>
        <Property label="Project" help="Optional Studio grouping. Moving a scenario may change its configuration for future checks and runs."><select aria-label="Project" value={item.project_id || ""} onChange={(event) => onProjectChange(event.target.value || null)}><option value="">Ungrouped</option>{snapshot.projects.map((project) => <option value={project.id} key={project.id}>{project.name}</option>)}</select></Property>
        {identity && <div className="identity-editor"><h3>Create draft with changed identity</h3><label>Identifier<div className="identity-input"><input aria-label="New identifier" value={identifier} onChange={(event) => setIdentifier(event.target.value)} /><button type="button" className="icon-button" aria-label="Suggest identifier" title="Suggest identifier from the display name" onClick={() => setIdentifier(suggestedIdentifier(displayName || properties.name))}><Sparkles size={16} /></button></div></label><label>Publisher<input aria-label="New publisher" value={publisher} onChange={(event) => setPublisher(event.target.value)} placeholder="Use inherited or configured publisher" /></label><p className="muted small">Creates a separate draft linked to this exact snapshot. Existing references keep pointing to the original identity.</p>{!!review?.name_consumers?.length && <details><summary>Existing consumers · {review.name_consumers.length}</summary><ul>{review.name_consumers.map((entry, index) => <li key={index}>{entry.name} {entry.version}</li>)}</ul></details>}{!!review?.name_review_problems?.length && <ul>{review.name_review_problems.map((problem) => <li key={problem}>{problem}</li>)}</ul>}<div className="job-actions"><button className="button-quiet" onClick={() => setIdentity(false)}>Cancel</button><button className="button-primary" disabled={busy || !review || (identifier === properties.name && publisher === (properties.lifecycle?.publisher || ""))} onClick={() => void newIdentity()}>Create linked draft</button></div></div>}
      </>}
      {section === "versions" && <><h2>Versions & publication</h2><ArtifactLifecycle item={item} api={api} onChanged={async () => { await onChanged(); setRefresh((value) => value + 1); }} onOpen={open} compact disabled={dirty} />
        {editable ? <ReleaseNotesField itemId={item.id} revision={properties.digest} value={notes} onChange={setNotes} onReviewed={(reviewed) => { if (reviewed.digest !== properties.digest) throw new Error("Source changed. Refresh Properties before requesting notes."); }} disabled={busy} api={api} help="Changes in this draft or release. Published notes are immutable and included in release integrity." /> : <Property label="Release notes" help="Notes describe this exact release; description is its overall scope."><p className="artifact-notes-text">{notes || "No release notes."}</p></Property>}
        <button className="text-button" onClick={() => setHistory(!history)} aria-expanded={history}>{history ? "Hide full history" : "View full history"}</button>
        {history && <div className="properties-history" aria-label="Release notes history">{(properties.history || []).map((entry) => <article key={entry.digest}><header><strong>{entry.publisher || "anonymous"}/{entry.name} · {entry.version || (entry.draft_id ? `Draft ${entry.draft_id.slice(0, 8)}` : "Legacy source")}</strong>{entry.path && <button className="button-quiet" disabled={dirty} onClick={() => void open(entry.path!)}>Open</button>}</header><small className="muted">{entry.digest}</small><p className="artifact-notes-text">{entry.available ? entry.notes || "No release notes." : "Exact ancestor is unavailable or has changed. Its notes cannot be verified."}</p></article>)}</div>}
        {!!properties.lifecycle?.parents?.length && <details className="properties-lineage"><summary>Parents · {properties.lifecycle.parents.length}</summary>{properties.lifecycle.parents.map((parent) => <article key={parent.digest}><strong>{parent.publisher || "anonymous"}/{parent.name} · {parent.version || "Draft / legacy source"}</strong><small className="property-code">{parent.digest}</small>{(properties.comparisons || []).find((comparison) => comparison.parent.digest === parent.digest)?.status === "available" && <details><summary>Compare authored files</summary>{Object.entries((properties.comparisons || []).find((comparison) => comparison.parent.digest === parent.digest)?.changes || {}).map(([name, changes]) => <div key={name}><strong>{name}</strong><pre>{changes}</pre></div>)}</details>}</article>)}</details>}
      </>}
      {section === "dependencies" && <><h2>Dependencies</h2>{(properties.dependencies || []).length ? (properties.dependencies || []).map((dependency, index) => <article className="property-dependency" key={index}><strong>{String(dependency.publisher || "anonymous")}/{String(dependency.name || "Dependency")} · {String(dependency.version || "draft")}</strong>{!!dependency.digest && <small className="property-code">{String(dependency.digest)}</small>}{!!dependency.source && <span className="muted small">{String(dependency.source)}</span>}</article>) : <p className="muted">No resolved pack dependencies.</p>}{(properties.findings || []).map((finding) => <p className="error-text" key={finding}>{finding}</p>)}</>}
      {section === "technical" && <><h2>Technical details</h2><Property label="Kind" help="Document family determines its schema and lifecycle operations.">{properties.kind}</Property><Property label="Schema" help="The format version, separate from the content release version. Upgrade creates a linked draft."><span>{properties.schema_version}</span>{properties.upgrade_available && <ArtifactLifecycle item={item} api={api} onChanged={onChanged} onOpen={open} compact disabled={dirty} />}</Property>
        <Property label="Validated with" help="Engine that successfully checked these exact inputs. Editing sources, dependencies or configuration makes a draft's check stale. This does not promise support on older engines."><span>{properties.validated_with ? `EvidenceForge ${properties.validated_with.evidenceforge_version} · ${new Date(properties.validated_with.completed_at).toLocaleString()}${properties.validated_with.warnings ? ` · ${properties.validated_with.warnings} warnings` : ""}` : "No recorded validation for these inputs"}</span><button className="button-quiet" disabled={busy || dirty} onClick={() => void validate()}>Validate</button></Property>
        <Property label="Content digest" help="Integrity identity for the complete source snapshot or published release."><code>{properties.digest}</code></Property>{properties.semantic_digest && <Property label="Generation digest" help="Generation-relevant content identity excludes notes and lineage."><code>{properties.semantic_digest}</code></Property>}{properties.lifecycle?.draft_id && <Property label="Draft identity" help="Unique draft identity stays the same across editing sessions."><code>{properties.lifecycle.draft_id}</code></Property>}<Property label="Source files" help="Authoritative YAML and includes. Published releases also retain frozen inputs and configuration."><ul>{(properties.source_files || []).map((path) => <li key={path}><code>{path}</code></li>)}</ul></Property>{properties.requires_evidenceforge && <details><summary>Advanced metadata</summary><Property label="Declared engine compatibility" help="Existing authored declaration, preserved as metadata. It is not inferred from every feature in the artifact."><code>{properties.requires_evidenceforge}</code></Property></details>}
      </>}
    </>}
  </PropertiesShell>;
}

export function BundlePropertiesDialog({ id, imported = false, api, onClose }: { id: string; imported?: boolean; api: StudioApi; onClose: () => void }) {
  const [section, setSection] = useState<PropertiesSection>("general");
  const [info, setInfo] = useState<BundleInfo | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { let live = true; void api.request<BundleInfo>(`/v1/${imported ? "bundles" : "jobs"}/${id}/properties`).then((value) => { if (live) setInfo(value); }).catch((failure) => { if (live) setError(String(failure)); }); return () => { live = false; }; }, [api, id, imported]);
  return <PropertiesShell title={info?.scenario || `Bundle ${id.slice(0, 8)}`} section={section} onSection={setSection} onClose={onClose} bundle>{error && <p role="alert" className="error-text">{error}</p>}{!info ? <p className="muted">Reading bundle properties…</p> : <><h2>{section === "dependencies" ? "Captured inputs" : section === "technical" ? "Technical details" : "General"}</h2>{section === "general" && <><Property label="Status" help="A completion manifest marks a finished generation. Partial runs retain their current output.">{info.complete ? "Completed" : "Partial output"}</Property><Property label="Scenario" help="Name captured when the run was generated.">{info.scenario || "Unavailable"}</Property><Property label="Created" help="Completion time captured in the run manifest.">{info.created_at ? new Date(info.created_at).toLocaleString() : "Not completed"}</Property><Property label="Bundle folder" help="Files captured by this run; changing the scenario does not change them."><code>{info.path}</code></Property></>}{section === "dependencies" && <><Property label="Scenario release" help="Exact authored identity captured for this run, when available.">{info.artifact?.name ? `${info.artifact?.publisher || "anonymous"}/${info.artifact?.name} · ${info.artifact?.version || "draft"}` : "No authored release identity recorded"}</Property><Property label="Packs" help="Exact pack selections captured for generation."><ul>{(info.selected_packs || []).map((pack, index) => <li key={index}>{String(pack.publisher)}/{String(pack.name)} · {String(pack.version)}<small className="property-code">{String(pack.digest || "")}</small></li>)}</ul></Property><Property label="Selected formats" help="Output selections captured for this run. Groups enable their supported types, but some may produce no log files.">{(info.formats || []).length ? (info.formats || []).map((format) => <span className="property-format" key={format}>{logTypeLabel(format)}</span>) : "No completion manifest available"}</Property><Property label="Execution overrides" help="Explicit run settings captured in provenance, independent of later workspace edits."><pre>{JSON.stringify(info.overrides, null, 2)}</pre></Property></>}{section === "technical" && <><Property label="Generated log data" help="Size of regular files under data/. Does not include metadata, checkpoints or ZIP compression.">{formatBundleSize(info.data_bytes)} · {info.data_files.toLocaleString()} files</Property><Property label="Total disk usage" help="All regular files in this bundle, including metadata and any checkpoints. ZIP size may differ.">{formatBundleSize(info.size_bytes)}</Property><Property label="Log types present" help="Specific types recognized from log filenames in this bundle. This does not imply every supported type, every event kind, or a record count.">{(info.log_types || []).length ? (info.log_types || []).map((format) => <span className="property-format" key={format}>{logTypeLabel(format)}</span>) : "None detected"}{!!info.unrecognized_data_files && <span className="muted small">{info.unrecognized_data_files.toLocaleString()} data {info.unrecognized_data_files === 1 ? "file has" : "files have"} an unrecognized log type.</span>}</Property><Property label="Generated with" help="Engine version captured by the run, not the current installed version.">{info.evidenceforge_version ? `EvidenceForge ${info.evidenceforge_version}` : "Unavailable"}</Property><Property label="Output target" help="Log representation captured by generation.">{info.output_target || "Unavailable"}</Property><Property label="Seed" help="Deterministic generation seed captured for this run.">{info.generation_seed ?? "Unavailable"}</Property><Property label="Compiled input digest" help="Identity of the captured generation inputs."><code>{info.compiled_sha256 || "Unavailable"}</code></Property></>}{(info.findings || []).map((finding) => <p className="muted small" key={finding}>{finding}</p>)}</>}</PropertiesShell>;
}
