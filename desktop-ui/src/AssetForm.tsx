import { useEffect, useState } from "react";
import { Plus, X } from "lucide-react";
import type { AssetChoices, AssetDetail, StudioApi } from "./api";
import { choicesFor, labelFor, resolveSchema, seedValue, type FieldSchema } from "./assetSchema";
import { includesPath, OverrideMark, sameValue, valueAt } from "./assetOverrides";

export type FormContext = { detail: AssetDetail; api: StudioApi; itemId: string; restoring?: string[]; onRestore?: (path: string) => void };

function ChoicePicker({ title, value, multiple, source, options, custom, disabled, onChange, context }: {
  title: string; value: unknown; multiple: boolean; source?: string; options?: string[];
  custom?: boolean; disabled?: boolean; onChange: (value: unknown) => void; context: FormContext;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [result, setResult] = useState<AssetChoices | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const selected = (multiple ? Array.isArray(value) ? value : [] : value ? [value] : []).map(String);
  useEffect(() => {
    if (!open || !source) return;
    let cancelled = false;
    setLoading(true); setError("");
    const timer = setTimeout(() => {
      const params = new URLSearchParams({ source, revision: context.detail.revision, query, page: String(page), page_size: "50" });
      void context.api.request<AssetChoices>(`/v1/items/${context.itemId}/assets/choices?${params}`, "GET", undefined, 180000).then((next) => { if (!cancelled) setResult(next); }).catch((reason) => { if (!cancelled) setError(String(reason)); }).finally(() => { if (!cancelled) setLoading(false); });
    }, 150);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [open, source, query, page, context.api, context.itemId, context.detail.revision]);
  const local = options?.filter((option) => option.toLowerCase().includes(query.toLowerCase())) || [];
  const entries = source ? result?.entries || [] : local;
  const matching = source ? result?.matching || 0 : local.length;
  function choose(option: string) {
    onChange(multiple ? selected.includes(option) ? selected.filter((entry) => entry !== option) : [...selected, option] : option);
    if (!multiple) setOpen(false);
  }
  return <div className="asset-choice-picker">
    <div className="asset-value-tags">{selected.length ? selected.map((entry) => <span className="asset-value-tag" key={entry}>{entry}<button type="button" disabled={disabled} aria-label={`Remove ${entry} from ${title}`} onClick={() => onChange(multiple ? selected.filter((option) => option !== entry) : null)}><X size={12} /></button></span>) : <span className="muted">None selected</span>}</div>
    <button type="button" className="button-quiet" disabled={disabled} aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Close choices" : `Choose ${title}`}</button>
    {open && <div className="asset-choice-options">
      <input autoFocus aria-label={`Search ${title} choices`} placeholder={`Search ${title.toLowerCase()}…`} value={query} maxLength={200} onChange={(event) => { setQuery(event.target.value); setPage(0); setResult(null); }} />
      {loading ? <p role="status" className="muted">Loading choices…</p> : <div role="listbox" aria-label={`${title} choices`} aria-multiselectable={multiple || undefined}>{entries.map((entry) => <button type="button" role="option" aria-selected={selected.includes(entry)} key={entry} onClick={() => choose(entry)}>{multiple && <span aria-hidden="true">{selected.includes(entry) ? "☑" : "☐"}</span>}{entry}</button>)}</div>}
      {!loading && !entries.length && <p className="muted">{query ? "No matching choices." : "No choices available yet. Add the referenced asset first."}</p>}
      {error && <p role="alert" className="field-error">{error}</p>}
      {custom && query.trim() && !entries.includes(query.trim()) && !selected.includes(query.trim()) && <button type="button" className="button-quiet" onClick={() => { choose(query.trim()); setQuery(""); }}>Add “{query.trim()}”</button>}
      {source && matching > 50 && <div className="asset-choice-pages"><button type="button" className="button-quiet" disabled={page === 0 || loading} onClick={() => { setPage(page - 1); setResult(null); }}>Previous choices</button><span>{page * 50 + 1}–{Math.min((page + 1) * 50, matching)} of {matching}</span><button type="button" className="button-quiet" disabled={(page + 1) * 50 >= matching || loading} onClick={() => { setPage(page + 1); setResult(null); }}>Next choices</button></div>}
      {custom && <small className="muted">Choose an existing label or search to add your own.</small>}
    </div>}
  </div>;
}

const fieldHelp: Record<string, string> = {
  username: "Unique account name; letters, digits, dots, underscores, hyphens and $ are allowed.",
  full_name: "Name shown for this account.", email: "A valid email address, such as alex@example.com.",
  hostname: "Unique hostname, such as WORKSTATION-01.", ip: "An IPv4 or IPv6 address.", os: "Operating system and version, such as Windows 11 or Ubuntu 24.04.",
  primary_system: "Choose this user's main computer from the systems in this environment.",
  groups: "Choose groups defined in this environment.", members: "Choose ordinary user accounts; stale accounts cannot be group members.",
  persona: "Each user has one behavior profile, which can include several activities. Leave unset for no persona activity.",
  enabled: "Active users can generate user activity; disabled users do not. Stale credentials are separate records used for failed logons and cannot share a username with an ordinary user.",
  permissions: "Descriptive permission labels. Choose existing labels or add a custom one.",
  roles: "Topology roles affect background activity. Choose a recognized role or an existing label.",
  services: "Services hosted by this system. Choose an existing service or add a label.",
  platforms: "Add a Windows or Linux definition, then fill in its executable fields.",
  image_path: "Full path to the executable on this platform.",
  command_templates: "Add the complete commands that launch this executable. Preserve any parameter placeholders.",
  deployment: "Choose how this executable is installed and versioned.",
  release_policy: "Choose how releases are selected for this executable.",
  pe_metadata: "Optional Windows executable metadata, such as product name and file version.",
  loaded_modules: "Optional libraries loaded by this process. Expand a module to edit its path and metadata.",
  last_active: "Last date this account was used; recorded for context.", reason: "Why these credentials are stale, such as a former employee or retired service.",
};

export function AssetFormFields({ schema, value, onChange, context, path = "", valuePath = [] }: {
  schema: FieldSchema; value: Record<string, unknown>; onChange: (value: Record<string, unknown>) => void; context: FormContext; path?: string; valuePath?: string[];
}) {
  return <div className="asset-form-fields">{Object.entries(schema.properties || {}).map(([name, raw]) => <AssetFormField key={name} name={name} path={path ? `${path} / ${labelFor(name, raw)}` : labelFor(name, raw)} valuePath={[...valuePath, name]} raw={raw} value={value[name]} required={schema.required?.includes(name) || false} disabled={!path && !!context.detail.summary && name === context.detail.identity_field} context={context} onChange={(next) => { const updated = { ...value }; if (next === undefined) delete updated[name]; else updated[name] = next; onChange(updated); }} />)}</div>;
}

function AssetFormField({ name, path, valuePath, raw, value, required, disabled, onChange, context }: {
  name: string; path: string; raw: FieldSchema; value: unknown; required: boolean;
  disabled?: boolean; onChange: (value: unknown) => void; context: FormContext; valuePath: string[];
}) {
  const [expanded, setExpanded] = useState(false);
  const schema = resolveSchema(raw, context.detail.schema_document, value);
  const title = labelFor(name, raw);
  const help = fieldHelp[name] || schema.description;
  const object = schema.type === "object" || !!schema.properties;
  const array = schema.type === "array";
  const empty = value === undefined || value === null;
  const options = schema["x-asset-enum"] || choicesFor(array ? resolveSchema(schema.items || {}, context.detail.schema_document) : schema);
  const source = schema["x-asset-choices"];
  const fieldPath = valuePath.join(".");
  const restoring = !disabled && includesPath(context.restoring, fieldPath);
  const customized = !!context.detail.inherited_value && !disabled && (includesPath(context.detail.override_fields, fieldPath) || !sameValue(value, valueAt(context.detail.inherited_value, valuePath)));
  const restore = customized && !restoring && context.onRestore && !valuePath.some((part) => /^\d+$/.test(part)) ? <button type="button" className="asset-unset" aria-label={`Restore inherited ${path}`} onClick={() => context.onRestore!(fieldPath)}>Restore inherited</button> : null;
  const mark = (customized || restoring) && <OverrideMark restoring={restoring} />;
  if (empty && !required) return <div className={`asset-form-field asset-field-wide ${customized || restoring ? "asset-field-customized" : ""}`}><div className="asset-field-heading">{mark}{restore}</div><details className="asset-optional"><summary>{title} <span className="muted">· Not set</span></summary>{help && <p className="muted">{help}</p>}<button type="button" className="button-quiet" disabled={disabled} onClick={() => onChange(seedValue(raw, context.detail.schema_document))}>Set {title}</button></details></div>;
  const control = source || (array && options) ? <ChoicePicker title={path} value={value} multiple={array} source={source} options={options} custom={schema["x-asset-custom"]} disabled={disabled} onChange={onChange} context={context} /> : object ? <ObjectFields name={name} path={path} valuePath={valuePath} raw={raw} schema={schema} value={(value || {}) as Record<string, unknown>} onChange={onChange} context={context} /> : array ? <ArrayFields path={path} valuePath={valuePath} schema={schema} value={Array.isArray(value) ? value : []} onChange={onChange} context={context} /> : schema.const !== undefined ? <span>{String(schema.const)}</span> : options ? <select aria-label={path} disabled={disabled} required={required} value={String(value ?? "")} onChange={(event) => onChange(event.target.value || null)}><option value="">Choose {title.toLowerCase()}</option>{options.map((option) => <option value={option} key={option}>{option}</option>)}</select> : schema.type === "boolean" ? <select aria-label={name === "enabled" ? "Account status" : path} disabled={disabled} value={String(value ?? false)} onChange={(event) => onChange(event.target.value === "true")}><option value="true">{name === "enabled" ? "Active" : "Yes"}</option><option value="false">{name === "enabled" ? "Disabled" : "No"}</option></select> : <input aria-label={path + (required ? " *" : "")} required={required} disabled={disabled} type={schema.type === "number" || schema.type === "integer" ? "number" : schema.format === "date" ? "date" : name === "email" ? "email" : "text"} step={schema.type === "integer" ? "1" : "any"} min={schema.minimum ?? (schema.exclusiveMinimum === undefined ? undefined : schema.exclusiveMinimum + (schema.type === "integer" ? 1 : Number.EPSILON))} max={schema.maximum} minLength={schema.minLength} maxLength={schema.maxLength} pattern={schema.pattern} value={String(value ?? "")} onChange={(event) => onChange(schema.type === "number" || schema.type === "integer" ? event.target.value === "" ? undefined : Number(event.target.value) : event.target.value)} />;
  const collapsible = (object || array) && ["deployment", "release_policy", "pe_metadata", "loaded_modules", "children", "child_templates"].includes(name);
  return <div className={`asset-form-field ${object || array || source ? "asset-field-wide" : ""} ${customized || restoring ? "asset-field-customized" : ""}`}>
    <div className="asset-field-heading"><span>{name === "enabled" ? "Account status" : title}{required && " *"}</span>{mark}{restore}{!required && !disabled && <button type="button" className="asset-unset" onClick={() => onChange(raw.default !== undefined ? structuredClone(raw.default) : array ? [] : undefined)} aria-label={`Reset ${path} to field default`}>{raw.default === null || raw.default === undefined ? "Clear field" : "Reset field default"}</button>}</div>
    {collapsible ? <details className="asset-nested-section" onToggle={(event) => setExpanded(event.currentTarget.open)}><summary>Edit {title.toLowerCase()}{Array.isArray(value) ? ` (${value.length})` : ""}</summary>{expanded && control}</details> : control}{help && <small className="muted">{help}</small>}
  </div>;
}

function ArrayFields({ path, valuePath, schema, value, onChange, context }: { path: string; valuePath: string[]; schema: FieldSchema; value: unknown[]; onChange: (value: unknown) => void; context: FormContext }) {
  const itemSchema = schema.items || {};
  return <div className="asset-array-fields">{value.map((entry, index) => <div className="asset-array-entry" key={index}><AssetFormField name={`Item ${index + 1}`} path={`${path} / Item ${index + 1}`} valuePath={[...valuePath, String(index)]} raw={itemSchema} value={entry} required onChange={(next) => onChange(value.map((old, position) => position === index ? next : old))} context={context} /><button type="button" className="button-quiet" aria-label={`Remove ${path} item ${index + 1}`} onClick={() => onChange(value.filter((_, position) => position !== index))}><X size={14} /></button></div>)}<button type="button" className="button-quiet" onClick={() => onChange([...value, seedValue(itemSchema, context.detail.schema_document)])}><Plus size={14} /> Add {path.split(" / ").pop()?.toLowerCase()} item</button></div>;
}

function ObjectFields({ name, path, valuePath, raw, schema, value, onChange, context }: { name: string; path: string; valuePath: string[]; raw: FieldSchema; schema: FieldSchema; value: Record<string, unknown>; onChange: (value: unknown) => void; context: FormContext }) {
  const [key, setKey] = useState("");
  const variants = (raw.anyOf || raw.oneOf)?.filter((entry) => entry.type !== "null").map((entry) => resolveSchema(entry, context.detail.schema_document)) || [];
  const kinds = variants.filter((entry) => entry.properties?.kind?.const !== undefined);
  const dictionary = !schema.properties;
  const keyOptions = schema.propertyNames?.enum?.map(String);
  const childSchema = typeof schema.additionalProperties === "object" ? schema.additionalProperties : Object.values(schema.patternProperties || {})[0] || {};
  const keyPattern = Object.keys(schema.patternProperties || {})[0];
  return <fieldset className="asset-object-fields" aria-label={path}>
    {kinds.length > 1 && <label>Definition type<select aria-label={`${path} definition type`} value={String(value.kind || kinds[0].properties?.kind.const)} onChange={(event) => { const branch = kinds.find((entry) => entry.properties?.kind.const === event.target.value)!; onChange(seedValue(branch, context.detail.schema_document)); }}>{kinds.map((entry) => <option value={String(entry.properties?.kind.const)} key={String(entry.properties?.kind.const)}>{String(entry.properties?.kind.const).replace(/_/g, " ")}</option>)}</select></label>}
    {dictionary ? <>
      {Object.entries(value).map(([entryKey, entry]) => <details key={entryKey} className="asset-map-entry" open><summary>{labelFor(entryKey)}</summary><AssetFormField name={entryKey} path={`${path} / ${labelFor(entryKey)}`} valuePath={[...valuePath, entryKey]} raw={childSchema.type || childSchema.$ref || childSchema.anyOf ? childSchema : { ...childSchema, type: Array.isArray(entry) ? "array" : typeof entry === "object" ? "object" : typeof entry }} value={entry} required onChange={(next) => onChange({ ...value, [entryKey]: next })} context={context} /><button type="button" className="asset-unset" aria-label={`Remove ${path} ${entryKey}`} onClick={() => { const next = { ...value }; delete next[entryKey]; onChange(next); }}>Remove {labelFor(entryKey)}</button></details>)}
      <div className="asset-map-add">{keyOptions ? <select aria-label={`New ${path} entry`} value={key} onChange={(event) => setKey(event.target.value)}><option value="">Choose {name === "platforms" ? "platform" : "entry"}</option>{keyOptions.filter((option) => !(option in value)).map((option) => <option key={option} value={option}>{labelFor(option)}</option>)}</select> : <input aria-label={`New ${path} entry`} placeholder={name === "pe_metadata" ? "Metadata field name" : "Entry name"} value={key} maxLength={200} onChange={(event) => setKey(event.target.value)} />}
      <button type="button" className="button-quiet" disabled={!key.trim() || key.trim() in value || (!!keyPattern && !new RegExp(keyPattern).test(key.trim()))} onClick={() => { onChange({ ...value, [key.trim()]: seedValue(childSchema, context.detail.schema_document) }); setKey(""); }}><Plus size={14} /> Add {name === "platforms" ? "platform" : "entry"}</button></div>
      {keyPattern && <small className="muted">Use a unique lowercase name with letters, digits, underscores or hyphens.</small>}
    </> : <AssetFormFields schema={schema} value={value} onChange={onChange} context={context} path={path} valuePath={valuePath} />}
  </fieldset>;
}
