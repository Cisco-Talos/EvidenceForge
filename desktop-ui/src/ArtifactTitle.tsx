import { useId, useState } from "react";
import { Check, Pencil, Sparkles, X } from "lucide-react";
import { DisplayNameField } from "./DisplayNameField";
import type { DisplayNameSource } from "./DisplayNameField";
import type { AffectedItem, StudioApi } from "./api";
import { AffectedItems } from "./AffectedItems";
import { artifactNameError, suggestedIdentifier } from "./artifactNaming";

export function ArtifactTitle({ name, displayName, api, source, prepareSource, prepareIdentifier, onSave, hint, kind = "scenario", disabled = false }: {
  name: string; displayName?: string | null; api: StudioApi; source: DisplayNameSource;
  prepareSource?: () => Promise<DisplayNameSource>; onSave: (displayName: string | null, name?: string) => Promise<void>;
  prepareIdentifier?: () => Promise<{ affected: AffectedItem[]; problems: string[] }>;
  hint?: string; kind?: "scenario" | "pack"; disabled?: boolean;
}) {
  const identifierId = useId();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(displayName || "");
  const [identifierOpen, setIdentifierOpen] = useState(false);
  const [identifier, setIdentifier] = useState(name);
  const [impact, setImpact] = useState<{ affected: AffectedItem[]; problems: string[] } | null>(null);
  const [saving, setSaving] = useState(false);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState("");

  async function edit() {
    setDraft(displayName || ""); setIdentifier(name); setIdentifierOpen(false); setImpact(null); setError(""); setEditing(true);
    if (!prepareSource) return;
    setReading(true);
    try { await prepareSource(); }
    catch (failure) { setError(String(failure)); }
    finally { setReading(false); }
  }
  async function save() {
    if (saving || reading || disabled) return;
    const title = draft.trim() || null;
    const nextName = identifierOpen ? identifier : name;
    const invalid = nextName !== name ? artifactNameError(nextName, kind) : null;
    if (invalid) { setError(invalid); return; }
    if (title === (displayName || null) && nextName === name) { setEditing(false); return; }
    setSaving(true); setError("");
    try { if (nextName !== name) await onSave(title, nextName); else await onSave(title); setEditing(false); }
    catch (failure) { setError(String(failure)); }
    finally { setSaving(false); }
  }
  async function reviewIdentifier() {
    setError(""); setImpact(null);
    if (!prepareIdentifier) return;
    setReading(true);
    try { setImpact(await prepareIdentifier()); }
    catch (failure) { setError(String(failure)); }
    finally { setReading(false); }
  }

  return editing ? <form className="artifact-title-edit" aria-label="Edit workspace display name" onSubmit={(event) => { event.preventDefault(); void save(); }} onKeyDown={(event) => { if (event.key === "Escape" && !saving) { event.preventDefault(); setEditing(false); } }}>
    <div className="artifact-title-controls"><DisplayNameField autoFocus label="Workspace display name" value={draft} onChange={(value) => { setDraft(value); setError(""); }} placeholder={name} disabled={saving || disabled} api={api} source={reading ? null : source} prepareSource={reading ? undefined : prepareSource} allowReplacement /><button className="icon-button" aria-label={identifierOpen ? "Save workspace names" : "Save workspace display name"} title={identifierOpen ? "Save names" : "Save display name"} disabled={saving || reading || disabled}><Check size={18} /></button><button type="button" className="icon-button" aria-label="Cancel display name edit" disabled={saving} onClick={() => setEditing(false)}><X size={18} /></button></div>
    <p className="muted small artifact-title-hint">{reading ? "Reading the current source…" : hint || "Leave empty to use the identifier."} <span title={name}>Identifier: {name}</span></p>
    <details className="artifact-identifier" open={identifierOpen} onToggle={(event) => {
      const open = event.currentTarget.open;
      if (open === identifierOpen) return;
      setIdentifierOpen(open);
      if (open) void reviewIdentifier(); else { setIdentifier(name); setError(""); }
    }}><summary>Change identifier</summary>{identifierOpen && <>
      <div className="modal-field"><div className="assisted-field-heading"><label htmlFor={identifierId}>Identifier</label><button type="button" className="icon-button ai-suggestion" aria-label="Suggest identifier" title="Suggest an identifier" disabled={saving || reading || disabled || !suggestedIdentifier(draft)} onClick={() => { setIdentifier(suggestedIdentifier(draft)); setError(""); }}><Sparkles size={16} /></button></div><input id={identifierId} value={identifier} disabled={saving || reading || disabled} onChange={(event) => { setIdentifier(event.target.value); setError(""); }} /></div>
      <p className="muted small">Changing the identifier starts a separate artifact identity. Published originals and existing references keep their identifiers. References to a renamed draft may need updating.</p>
      {!!impact?.affected.length && <><p className="muted small">{impact.affected.length} other {impact.affected.length === 1 ? "artifact references" : "artifacts reference"} this pack.</p><AffectedItems items={impact.affected} /></>}
      {!!impact?.problems.length && <p className="field-error">Some references could not be checked: {impact.problems.join("; ")}</p>}
    </>}</details>
    {error && <p className="field-error" role="alert">{error}</p>}
  </form> : <h1 aria-label={displayName || name}><button className="scenario-title-button" aria-label={`Edit display name ${displayName || name}`} title={`Edit display name. Identifier: ${name}`} disabled={disabled} onClick={() => void edit()}>{displayName || name}<Pencil size={18} /></button></h1>;
}
