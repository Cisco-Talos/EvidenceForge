import { useState } from "react";
import { Check, Pencil, X } from "lucide-react";
import { scenarioNameError } from "./scenarioName";

export function ScenarioTitle({ name, onRename }: {
  name: string; onRename: (name: string) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(name);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const invalid = scenarioNameError(draft);

  async function save() {
    if (invalid || saving) return;
    if (draft === name) { setEditing(false); return; }
    setSaving(true); setError(null);
    try { await onRename(draft); setEditing(false); }
    catch (reason) { setError(String(reason)); }
    finally { setSaving(false); }
  }

  return editing ? <form className="scenario-title-edit" onSubmit={(event) => { event.preventDefault(); void save(); }}>
    <div><input autoFocus aria-label="Scenario Name" name="scenario-name" autoComplete="off" maxLength={80} value={draft} disabled={saving} aria-invalid={!!invalid} aria-describedby={invalid || error ? "scenario-title-error" : undefined} onChange={(event) => { setDraft(event.target.value); setError(null); }} onKeyDown={(event) => { if (event.key === "Escape" && !saving) { event.preventDefault(); setEditing(false); } }} /><button className="icon-button" aria-label="Save scenario name" disabled={saving || !!invalid}><Check size={18} /></button><button type="button" className="icon-button" aria-label="Cancel scenario rename" disabled={saving} onClick={() => setEditing(false)}><X size={18} /></button></div>
    {(invalid || error) && <p id="scenario-title-error" className="field-error" role="status">{invalid || error}</p>}
  </form> : <h1 aria-label={name}><button className="scenario-title-button" aria-label={`Rename scenario ${name}`} title="Rename scenario" onClick={() => { setDraft(name); setError(null); setEditing(true); }}>{name}<Pencil size={18} /></button></h1>;
}
