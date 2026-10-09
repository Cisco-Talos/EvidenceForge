import { Fragment, useEffect, useState } from "react";
import { ChevronRight, FileText, Package, Pencil, Plus, RotateCcw, Search, Settings2 } from "lucide-react";
import { Tooltip } from "radix-ui";
import type { AssetDetail, AssetOrigin, AssetPage, AssetSaved, CatalogItem, StudioApi } from "./api";
import { Pagination } from "./Pagination";
import { AssetFormFields } from "./AssetForm";
import { AssetValue } from "./AssetValue";
import { fieldErrors, seedValue, type FieldSchema } from "./assetSchema";
import { includesPath, OverrideMark, restoreValue, retainRestorations, sameValue } from "./assetOverrides";

type View = { category: string; query: string; origin: string; source: string; page: number; size: number; expanded: string | null; status: string };
const initialView: View = { category: "", query: "", origin: "", source: "", page: 0, size: 50, expanded: null, status: "" };
const originNames = { scenario: "Scenario", pack: "Pack", mixed: "Pack with scenario overrides", configuration: "Configuration / defaults" };

function OriginBadge({ origin }: { origin: AssetOrigin }) {
  return <Tooltip.Root><Tooltip.Trigger asChild><span tabIndex={0} className={`asset-origin asset-origin-${origin.kind}`} aria-label={`${originNames[origin.kind]}: ${origin.source}`}>
    {origin.kind === "scenario" ? <FileText size={16} /> : origin.kind === "configuration" ? <Settings2 size={16} /> : <Package size={16} />}
    {origin.kind === "mixed" && <Pencil className="asset-origin-pencil" size={9} />}
  </span></Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="tooltip" sideOffset={5}>{originNames[origin.kind]} · {origin.source}<Tooltip.Arrow /></Tooltip.Content></Tooltip.Portal></Tooltip.Root>;
}

function sourceLabel(source: string): string {
  return source.split(" · ").map((part) => part.startsWith("/") ? part.split("/").pop() : part).join(" · ");
}

const categoryGuides: Record<string, { title: string; description: string }> = {
  users: { title: "User account", description: "Add a named account with an email address. Choose its main system, groups and behavior profile." },
  stale_accounts: { title: "Stale account", description: "Add retired credentials that produce occasional failed logons. This account has no ordinary user activity." },
  groups: { title: "Group", description: "Name the group, then choose its members from existing user accounts." },
  systems: { title: "System", description: "Give the computer a unique hostname and address, choose its type, then add roles and hosted services." },
  network_identities: { title: "Network identity", description: "Give this identity a unique ID and at least one hostname or IP address." },
  dns: { title: "DNS entry", description: "Define a domain and its address pool, then choose the tags used to select it." },
  applications: { title: "Application", description: "Define the application's ID, display name and eligible users, then add a Windows or Linux executable definition." },
  processes: { title: "Process definition", description: "Define an executable with a unique application ID, eligibility and a Windows or Linux platform definition." },
  persona_catalog: { title: "Persona", description: "Name a reusable behavior profile and describe its work hours, activities and browsing intensity." },
  process_catalog: { title: "Process profile", description: "Choose built-in executables, or add custom executable definitions with platform-specific paths and commands." },
  application_catalog: { title: "Application profile", description: "Choose existing persona and process profiles. Optional connections refer to destination profiles." },
  destination_catalog: { title: "Destination profile", description: "Define endpoints with domains and address pools, plus the services they expose." },
  traffic_catalog: { title: "Traffic profile", description: "Describe reusable traffic behavior and choose its audience and destination profiles." },
  storage_catalog: { title: "Storage profile", description: "Define the reusable storage layout and vocabulary for files and shares." },
};

function AssetEditor({ detail, isPack, api, itemId, onCancel, onSaved, restoreAll = false }: {
  detail: AssetDetail; isPack: boolean; api: StudioApi; itemId: string; onCancel: () => void; onSaved: (saved: AssetSaved) => Promise<void>; restoreAll?: boolean;
}) {
  const [value, setValue] = useState<Record<string, unknown>>(() => restoreAll && detail.inherited_value ? structuredClone(detail.inherited_value) : detail.summary ? structuredClone(detail.value) : seedValue(detail.schema_document as FieldSchema, detail.schema_document) as Record<string, unknown>);
  const [restoring, setRestoring] = useState<string[]>(restoreAll ? ["*"] : []);
  const [key, setKey] = useState(detail.summary?.key || "");
  const allocateVersion = isPack && detail.next_version != null;
  const [version, setVersion] = useState(detail.next_version || "");
  const [reviewing, setReviewing] = useState(restoreAll);
  const [checking, setChecking] = useState(false);
  const [blockers, setBlockers] = useState<string[]>([]);
  const [effects, setEffects] = useState(detail.conversion_effects || []);
  const converting = !!detail.conversion_from;
  const before = detail.previous_value || detail.value;
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [attempted, setAttempted] = useState(false);
  const changed = [...new Set([...Object.keys(value), ...(converting ? [] : Object.keys(before))])].filter((name) => (converting ? value[name] != null && (!Array.isArray(value[name]) || (value[name] as unknown[]).length > 0) : true) && (!sameValue(value[name], before[name]) || (name !== detail.identity_field && includesPath(restoring, name) && includesPath(detail.override_fields, name))));
  const problems = fieldErrors(detail.schema_document as FieldSchema, detail.schema_document, value);
  if (detail.identity_field === "key" && !/^[a-z0-9][a-z0-9_-]*$/.test(key)) problems.unshift("Catalog key needs lowercase letters, digits, underscores or hyphens.");
  if (allocateVersion && !/^\d+\.\d+\.\d+$/.test(version)) problems.push("New version needs three numbers, such as 1.0.1.");
  const guide = categoryGuides[detail.category];
  const context = { detail, api, itemId, restoring, onRestore: (path: string) => {
    if (!detail.inherited_value) return;
    setValue((current) => restoreValue(current, detail.inherited_value!, path));
    setRestoring((current) => [...current.filter((entry) => entry !== path && !entry.startsWith(path + ".")), path]);
  } };
  function payload(preview = false) {
    return { revision: detail.revision, category: detail.category, asset_id: detail.summary?.id || null, key: detail.identity_field === "key" ? key : String(value[detail.identity_field] || ""), value, version: allocateVersion ? version : null, ...(restoring.length ? { restore_fields: restoring } : {}), ...(converting ? { convert_from: detail.conversion_from, ...(preview ? { preview: true } : {}) } : {}) };
  }
  async function review() {
    setAttempted(true);
    if (problems.length) return;
    if (!converting) { setReviewing(true); return; }
    setChecking(true); setError("");
    try {
      const result = await api.request<AssetSaved>(`/v1/items/${itemId}/assets`, "POST", payload(true), 180000);
      setBlockers(result.validation_errors || []); setEffects(result.effects || []); setReviewing(true);
    } catch (reason) { setError(String(reason)); }
    finally { setChecking(false); }
  }
  async function save() {
    setSaving(true); setError("");
    try {
      const saved = await api.request<AssetSaved>(`/v1/items/${itemId}/assets`, "POST", payload(), 180000);
      await onSaved(saved);
    } catch (reason) { setError(String(reason)); }
    finally { setSaving(false); }
  }
  return <form className="asset-editor" aria-label={detail.summary ? `Edit ${detail.summary.name}` : `Add ${guide?.title.toLowerCase() || "asset"}`} noValidate onSubmit={(event) => { event.preventDefault(); void review(); }}>
    <h3>{converting ? `${detail.category === "stale_accounts" ? "Mark as stale" : "Restore as user"}: ${detail.summary?.name}` : detail.summary ? `${isPack || detail.summary.origin.kind === "scenario" ? "Edit" : "Customize"} ${detail.summary.name}` : `Add ${guide?.title.toLowerCase() || "asset"}`}</h3>
    <p className="asset-editor-guidance">{!detail.summary && guide?.description} {allocateVersion ? "Saving creates a new pack version. Existing scenarios keep their selected version." : "Changes stay in this draft until you publish."}</p>
    {converting && <p className="asset-inheritance-guide">{detail.category === "stale_accounts" ? "This account will become stale credentials used for failed logons. Its user details are retained for restoration. Review the date, reason and affected relationships before saving." : "This account will become a regular user. Saved user details are filled in when available; choose Active or Disabled and review its system, groups and persona."}</p>}
    {!reviewing ? <>
      <p className="muted">Fields marked * are required. Choose references from the available assets; optional fields can use their defaults.</p>
      {detail.identity_field === "key" && <label>Catalog key *<input required pattern="[a-z0-9][a-z0-9_-]*" value={key} disabled={!!detail.summary} onChange={(event) => { setKey(event.target.value); setError(""); }} /><small className="muted">Unique lowercase name for this export, such as billing_tools.</small></label>}
      {detail.inherited_value && <p className="asset-inheritance-guide"><Pencil size={14} /> Highlighted fields are customized in this scenario. “Restore inherited” removes an override; “Clear field” explicitly clears a value. Restore changes take effect after review and save.</p>}
      <AssetFormFields schema={detail.schema_document as FieldSchema} value={value} onChange={(next) => { setValue(next); if (detail.inherited_value) setRestoring((current) => retainRestorations(current, next, detail.inherited_value!).filter((path) => path !== detail.identity_field)); setError(""); }} context={context} />
      {allocateVersion && <label>New version<input required pattern="\d+\.\d+\.\d+" value={version} onChange={(event) => setVersion(event.target.value)} /></label>}
      {attempted && problems.length > 0 && <div role="alert" className="asset-form-errors"><strong>Complete these fields before reviewing:</strong><ul>{problems.map((problem) => <li key={problem}>{problem}</li>)}</ul></div>}
    </> : <div className="asset-review"><h4>{converting ? "Review account conversion" : restoreAll ? "Restore inherited values" : allocateVersion ? `Create version ${version}` : "Review scenario changes"}</h4>{restoring.length > 0 && <p className="asset-inheritance-guide">{restoring.includes("*") ? "All scenario customizations on this asset will be removed." : "The marked overrides will be removed."} These values will come from the selected pack or configuration again.</p>}{!detail.summary && <p>New {guide?.title.toLowerCase() || "asset"}: {key || String(value[detail.identity_field] || "")}</p>}<dl>{changed.map((name) => <Fragment key={name}><dt>{name.replace(/_/g, " ")} {includesPath(restoring, name) && <OverrideMark restoring />}</dt><dd>{detail.summary && <div className="asset-review-before"><small>Before</small><AssetValue value={before[name]} /></div>}<div><small>{detail.summary ? "After" : "Value"}</small><AssetValue value={value[name]} /></div></dd></Fragment>)}</dl></div>}
    {converting && reviewing && <div className="asset-conversion-review"><p><strong>Account status:</strong> {detail.conversion_from === "stale_accounts" ? "Stale" : before.enabled === false ? "Disabled" : "Active"} → {detail.category === "stale_accounts" ? "Stale" : value.enabled === false ? "Disabled" : "Active"}</p>{effects.length > 0 && <><strong>Affected relationships</strong><ul>{effects.map((effect) => <li key={effect}>{effect}</li>)}</ul><p className="muted">These directory links are retained in the scenario source and become effective again when the account is restored.</p></>}{blockers.length > 0 && <div role="alert" className="asset-form-errors"><strong>Resolve these references before converting:</strong><ul>{blockers.map((problem) => <li key={problem}>{problem}</li>)}</ul><p>Cancel, update the referenced assets or storyline, then try again.</p></div>}</div>}
    {error && <p role="alert" className="field-error">{error}</p>}
    <footer><button type="button" className="button-quiet" disabled={saving || checking} onClick={onCancel}>Cancel</button>{reviewing ? <><button type="button" className="button-quiet" disabled={saving || checking} onClick={() => setReviewing(false)}>Back to edit</button><button type="button" className="button-primary" disabled={saving || checking || blockers.length > 0 || problems.length > 0 || !changed.length || (allocateVersion && !/^\d+\.\d+\.\d+$/.test(version))} onClick={() => void save()}>{saving ? "Validating and saving…" : allocateVersion ? "Create new version" : "Save draft"}</button></> : <button className="button-primary" disabled={checking || !changed.length}>{checking ? "Checking account references…" : "Review changes"}</button>}</footer>
  </form>;
}

function AssetFields({ detail }: { detail: AssetDetail }) {
  return <><h3 className="asset-detail-heading">{detail.summary?.name} details</h3><dl className="asset-fields">{Object.entries(detail.value).map(([name, value]) => {
    const origins = Object.entries(detail.field_origins).filter(([path]) => path === name || path.startsWith(name + "."));
    const unique = [...new Map(origins.map(([, origin]) => [`${origin.kind}:${origin.source}`, origin])).values()];
    const customized = !!detail.inherited_value && includesPath(detail.override_fields, name);
    return <Fragment key={name}><dt className={customized ? "asset-customized-value" : ""}>{name.replace(/_/g, " ")} {customized && <OverrideMark />}<span>{unique.map((origin) => <OriginBadge key={`${origin.kind}:${origin.source}`} origin={origin} />)}</span></dt><dd className={customized ? "asset-customized-value" : ""}><AssetValue value={value} path={name} overrides={detail.inherited_value ? detail.override_fields : undefined} />{unique.length > 1 && <details><summary>Field sources</summary>{origins.map(([path, origin]) => <p key={path}><OriginBadge origin={origin} /><code>{path}</code><small>{origin.source}</small></p>)}</details>}</dd></Fragment>;
  })}</dl></>;
}

function AddAssetChooser({ categories, selected, isPack, onChoose, onCancel }: {
  categories: AssetPage["categories"]; selected: string; isPack: boolean; onChoose: (category: string) => void; onCancel: () => void;
}) {
  const [category, setCategory] = useState(selected);
  const [accountKind, setAccountKind] = useState("users");
  const chosen = category === "users" ? accountKind : category;
  const guide = categoryGuides[chosen];
  return <section className="asset-expanded asset-add-chooser" aria-label="Choose asset type"><h3>What would you like to add?</h3><p className="muted">{isPack ? "Create a reusable asset in a new version of this pack." : "Create an asset owned by this scenario."} The next step guides you through the required fields. Changes are validated before saving.</p>
    <label>Asset type<select aria-label="Asset type" value={category} onChange={(event) => setCategory(event.target.value)}>{categories.filter((entry) => entry.editable).map((entry) => <option value={entry.key} key={entry.key}>{entry.label}</option>)}</select></label>
    {category === "users" && <label>Account kind<select aria-label="Account kind" value={accountKind} onChange={(event) => setAccountKind(event.target.value)}><option value="users">Ordinary user account</option><option value="stale_accounts">Stale credentials</option></select></label>}
    <p className="asset-editor-guidance">{guide?.description}</p><div className="asset-chooser-actions"><button type="button" className="button-quiet" onClick={onCancel}>Cancel</button><button type="button" className="button-primary" onClick={() => onChoose(chosen)}>Continue with {guide?.title.toLowerCase() || "asset"}</button></div>
  </section>;
}

export function AssetBrowser({ item, api, refreshVersion, onChanged }: {
  item: CatalogItem; api: StudioApi; refreshVersion?: number | string; onChanged?: () => Promise<void>;
}) {
  const storageKey = `studio-assets:${item.id}`;
  const [view, setView] = useState<View>(() => { try { const saved = JSON.parse(sessionStorage.getItem(storageKey) || "{}"); return { ...initialView, ...saved, ...(saved.category === "stale_accounts" ? { category: "users", status: "stale" } : {}) }; } catch { return initialView; } });
  const [page, setPage] = useState<AssetPage | null>(null);
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [editing, setEditing] = useState(false);
  const [restoringAll, setRestoringAll] = useState(false);
  const [adding, setAdding] = useState(false);
  const [newCategory, setNewCategory] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  const isPack = item.kind !== "scenario";
  const filter = (patch: Partial<View>) => { setRestoringAll(false); setEditing(false); setAdding(false); setDetail(null); setView((current) => ({ ...current, ...patch, ...(patch.category ? { status: "" } : {}), page: 0, expanded: null })); };
  useEffect(() => { try { sessionStorage.setItem(storageKey, JSON.stringify(view)); } catch { /* Views remain usable without storage. */ } }, [view, storageKey]);
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError(""); setDetail(null);
    const timer = setTimeout(() => {
      const params = new URLSearchParams({ category: view.category, query: view.query, origin: view.origin, source: view.source, page: String(view.page), page_size: String(view.size), account_status: view.status });
      void api.request<AssetPage>(`/v1/items/${item.id}/assets?${params}`, "GET", undefined, 180000).then((result) => {
        if (!cancelled) { setPage(result); setView((current) => ({ ...current, category: result.category, page: result.page })); }
      }).catch((reason) => { if (!cancelled) { setError(String(reason)); setPage(null); } }).finally(() => { if (!cancelled) setLoading(false); });
    }, 200);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [api, item.id, item.source_sha256, refreshVersion, reload, view.category, view.query, view.origin, view.source, view.page, view.size, view.status]);
  useEffect(() => {
    if (!view.expanded || !page || loading) return;
    let cancelled = false;
    setDetail(null); setError("");
    const params = new URLSearchParams({ category: view.expanded === "new" ? newCategory || page.category : page.category, revision: page.revision });
    if (view.expanded !== "new") params.set("asset_id", view.expanded);
    void api.request<AssetDetail>(`/v1/items/${item.id}/assets/detail?${params}`, "GET", undefined, 180000).then((result) => { if (!cancelled) setDetail(result); }).catch((reason) => { if (!cancelled) setError(String(reason)); });
    return () => { cancelled = true; };
  }, [api, item.id, view.expanded, page?.revision, page?.category, loading, newCategory]);
  function close() { setEditing(false); setRestoringAll(false); setAdding(false); setView((current) => ({ ...current, expanded: null })); }
  async function saved(result: AssetSaved) {
    setNotice(result.version ? `Created version ${result.version}. The original version remains selected here; open the new version from Packs to continue editing.` : "Scenario saved. Validation and run status now reflect the changed inputs.");
    close(); setReload((current) => current + 1); await onChanged?.();
  }
  async function convertAccount() {
    if (!detail?.summary) return;
    setError("");
    try {
      const params = new URLSearchParams({ category: detail.category, asset_id: detail.summary.id, revision: detail.revision, conversion: "true" });
      const draft = await api.request<AssetDetail>(`/v1/items/${item.id}/assets/detail?${params}`, "GET", undefined, 180000);
      setDetail(draft); setRestoringAll(false); setEditing(true);
    } catch (reason) { setError(String(reason)); }
  }
  const canEdit = page?.categories.some((category) => category.editable !== false) !== false;
  const body = detail ? editing || view.expanded === "new" ? <AssetEditor key={`${detail.revision}:${detail.summary?.id || "new"}:${restoringAll}:${detail.conversion_from || ""}`} detail={detail} isPack={isPack} api={api} itemId={item.id} onCancel={close} onSaved={saved} restoreAll={restoringAll} /> : <>{canEdit && <div className="asset-detail-actions"><button className="button-quiet" onClick={() => { setRestoringAll(false); setEditing(true); }}><Pencil size={14} />{isPack || detail.summary?.origin.kind === "scenario" ? "Edit" : "Customize in scenario"}</button>{!isPack && detail.inherited_value && !!detail.override_fields?.length && <button className="button-quiet" onClick={() => { setRestoringAll(true); setEditing(true); }}><RotateCcw size={14} />Restore inherited values</button>}{!isPack && detail.summary && ["users", "stale_accounts"].includes(detail.category) && <button className="button-quiet" onClick={() => void convertAccount()}><RotateCcw size={14} />{detail.category === "users" ? "Mark as stale…" : "Restore as user…"}</button>}</div>}<AssetFields detail={detail} /></> : <p role="status" className="muted">Loading asset details…</p>;
  return <section className="asset-browser surface" aria-label={isPack ? "Pack assets" : "Environment assets"} aria-busy={loading}>
    <header className="asset-browser-heading"><h2>{isPack ? "Pack assets" : "Assets"}</h2><button className="button-quiet" disabled={!page || loading || !canEdit} onClick={() => { setRestoringAll(false); setAdding(true); setEditing(false); setDetail(null); setView((current) => ({ ...current, expanded: null })); }}><Plus size={15} /> Add asset</button></header>
    <div className="asset-categories" aria-label="Asset categories">{page?.categories.map((category) => <button className={`button-quiet ${page.category === category.key ? "active" : ""}`} key={category.key} aria-pressed={page.category === category.key} onClick={() => filter({ category: category.key })}>{category.label} <small>{category.total.toLocaleString()}</small></button>)}</div>
    <div className="asset-filters"><div className="search-box"><Search size={15} /><input aria-label="Search assets" maxLength={200} placeholder="Search names, addresses, groups, or values…" value={view.query} onChange={(event) => filter({ query: event.target.value })} /></div><select aria-label="Filter asset origins" value={view.origin} onChange={(event) => filter({ origin: event.target.value })}><option value="">All origins</option>{Object.entries(originNames).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select><input aria-label="Filter asset source" maxLength={200} placeholder="Pack or source file…" value={view.source} onChange={(event) => filter({ source: event.target.value })} /></div>
    {error && <p role="alert" className="field-error">{error} <button className="button-quiet" onClick={() => setReload((current) => current + 1)}>Refresh assets</button></p>}
    {notice && <p role="status" className="run-revision-note">{notice}</p>}
    {adding && page && <AddAssetChooser categories={page.categories} selected={page.category} isPack={isPack} onCancel={close} onChoose={(category) => { setRestoringAll(false); setNewCategory(category); setAdding(false); setEditing(true); setDetail(null); setView((current) => ({ ...current, expanded: "new" })); }} />}
    {page?.category === "users" && <div className="asset-account-guide"><label>Account status<select aria-label="Filter account status" value={view.status} onChange={(event) => filter({ status: event.target.value })}><option value="">All accounts</option><option value="active">Active</option><option value="disabled">Disabled</option><option value="stale">Stale</option></select></label><small>Disabled users produce no user activity. Stale credentials produce occasional failed logons.</small></div>}
    {view.expanded === "new" && !loading && <div className="asset-expanded">{body}</div>}
    {loading ? <p role="status" className="muted">Loading assets…</p> : page && <>
      <p className="muted asset-result-count">{page.matching.toLocaleString()} matching · {page.total.toLocaleString()} total</p>
      <table className="asset-table"><thead><tr><th aria-label="Origin" className="asset-origin-column" /><th>Asset</th><th>Details</th><th>Source</th></tr></thead><tbody>{page.entries.map((entry) => <Fragment key={entry.id}><tr className={view.expanded === entry.id ? "expanded" : ""}><td className="asset-origin-column"><OriginBadge origin={entry.origin} /></td><td><button className="asset-row-toggle" aria-expanded={view.expanded === entry.id} onClick={() => { setRestoringAll(false); setEditing(false); setDetail(null); setView((current) => ({ ...current, expanded: current.expanded === entry.id ? null : entry.id })); }}><ChevronRight size={15} className={`disclosure-chevron ${view.expanded === entry.id ? "expanded" : ""}`} />{entry.name}</button>{entry.account_status && <span className={`asset-account-status asset-account-${entry.account_status}`}>{entry.account_status}</span>}</td><td>{entry.description}</td><td className="asset-source" title={entry.origin.source}>{sourceLabel(entry.origin.source)}</td></tr>{view.expanded === entry.id && <tr className="asset-detail-row"><td colSpan={4}><div className="asset-expanded">{body}</div></td></tr>}</Fragment>)}</tbody></table>
      {!page.entries.length && <p className="muted">{page.total ? "No assets match these filters." : "No assets in this category yet."}</p>}
      <div className="asset-page-controls"><label>Rows per page<select aria-label="Assets per page" value={view.size} onChange={(event) => filter({ size: Number(event.target.value) })}>{[25, 50, 100].map((size) => <option key={size} value={size}>{size}</option>)}</select></label><Pagination page={page.page} pageSize={page.page_size} matching={page.matching} unit="assets" label="Asset pages" names={{ first: "First assets page", previous: "Previous assets", next: "Next assets", last: "Last assets page", page: (number) => `Assets page ${number}` }} onPage={(next) => { setEditing(false); setView((current) => ({ ...current, page: next, expanded: null })); }} /></div>
    </>}
  </section>;
}
