import { useEffect, useRef, useState } from "react";
import { Check, FileCode2, Layers3, RefreshCw, Search, SquarePen } from "lucide-react";
import { Dialog } from "radix-ui";
import type { CatalogItem, EnvironmentReport, SelectedPack, StudioApi } from "./api";
import { BundleFileBrowser } from "./BundleFileBrowser";
import { CopyPathButton } from "./CopyPathButton";
import { ChatMarkdown } from "./ChatMarkdown";

export function packReference(pack: Pick<SelectedPack, "source" | "publisher" | "type" | "name" | "version" | "location">): string {
  return pack.source === "path" ? pack.location : `${pack.source}:${pack.publisher}:${pack.type}:${pack.name}@${pack.version}`;
}

type PackChoice = { key: string; label: string; kind: string; reference: string; author: string; version: string; source: string };

function PackPicker({ report, packs, onClose, onPrepare, onError, onReturnFocus }: {
  report: EnvironmentReport; packs: CatalogItem[]; onClose: () => void; onReturnFocus: () => void; onPrepare: (prompt: string) => Promise<void>; onError: (message: string) => void;
}) {
  const organization = report.selected_packs.find((pack) => pack.type === "organization");
  const [mode, setMode] = useState<"none" | "industries" | "organization">(organization ? "organization" : report.selected_packs.length ? "industries" : "none");
  const initial = report.selected_packs.filter((pack) => organization ? pack.type === "organization" : true).map(packReference);
  const [selected, setSelected] = useState(initial);
  const [query, setQuery] = useState("");
  const [working, setWorking] = useState(false);
  const choices: PackChoice[] = packs.filter((pack) => pack.publisher && pack.version).map((pack) => {
    const source = pack.pack_source === "bundled" ? "package" : "project";
    const kind = pack.kind === "industry_pack" ? "industry" : "organization";
    const reference = `${source}:${pack.publisher}:${kind}:${pack.name}@${pack.version}`;
    return { key: reference, label: pack.name, kind, reference, author: pack.publisher_display_name || pack.publisher || "", version: pack.version, source };
  });
  for (const pack of report.selected_packs) {
    const reference = packReference(pack);
    if (!choices.some((choice) => choice.key === reference)) choices.push({ key: reference, label: pack.name, kind: pack.type, reference, author: pack.publisher, version: pack.version, source: pack.source });
  }
  const activeKind = mode === "organization" ? "organization" : "industry";
  const active = mode === "none" ? [] : choices.filter((choice) => choice.kind === activeKind && selected.includes(choice.key));
  async function prepare() {
    setWorking(true);
    try {
      await onPrepare([
        "Please update this scenario's environment composition using the EvidenceForge scenario and pack workflows.",
        active.length ? `Use these exact ${activeKind === "organization" ? "organization pack (including its locked industry dependencies)" : "industry packs"}:` : "Remove pack composition and retain a self-contained authored environment.",
        ...active.map((choice) => `- ${choice.reference} (${choice.label} ${choice.version}, publisher ${choice.author})`),
        "Inspect the current scenario, nested includes, selected pack exports, and merge origins first. Explain which authored fields would override the chosen pack and propose edits before applying them. Preserve unrelated scenario content, supporting files, safety settings, and existing bundles. If conversion from Scenario 1.0 is needed, explain it. Revalidate and explain composition after the edits.",
      ].join("\n"));
      onClose();
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); }
  }
  return <Dialog.Root open onOpenChange={(open) => !open && !working && onClose()}><Dialog.Portal><Dialog.Overlay className="radix-dialog-overlay" /><Dialog.Content className="environment-picker" aria-describedby="pack-picker-help" onCloseAutoFocus={(event) => { event.preventDefault(); onReturnFocus(); }}><Dialog.Title>Choose environment packs</Dialog.Title><Dialog.Description id="pack-picker-help">Choose exact versions. This prepares a request in a new conversation so you can review how the packs fit your scenario.</Dialog.Description>
    <fieldset className="pack-mode"><legend>Composition</legend>{(["none", "industries", "organization"] as const).map((choice) => <label key={choice}><input type="radio" name="composition-mode" checked={mode === choice} onChange={() => setMode(choice)} />{choice === "none" ? "No packs" : choice === "industries" ? "Industry packs" : "One organization"}</label>)}</fieldset>
    {mode !== "none" && <><div className="search-box"><Search size={15} /><input aria-label="Search environment packs" placeholder="Search name, author, or version…" value={query} onChange={(event) => setQuery(event.target.value)} /></div><ul className="pack-choice-list">{choices.filter((choice) => choice.kind === activeKind && `${choice.label} ${choice.author} ${choice.version} ${choice.reference}`.toLowerCase().includes(query.toLowerCase())).map((choice) => <li key={choice.key}><label><input type={mode === "organization" ? "radio" : "checkbox"} name={mode === "organization" ? "organization-pack" : undefined} checked={selected.includes(choice.key)} onChange={(event) => setSelected(mode === "organization" ? [choice.key] : event.target.checked ? [...selected, choice.key] : selected.filter((key) => key !== choice.key))} /><span><strong>{choice.label} <small>{choice.version}</small></strong><small>{choice.author} · {choice.source}</small><code>{choice.reference}</code></span></label></li>)}</ul>{!active.length && <p className="muted">Select {mode === "organization" ? "an organization" : "at least one industry pack"}.</p>}</>}
    <footer><Dialog.Close className="button-quiet" disabled={working}>Cancel</Dialog.Close><button className="button-primary" disabled={working || (mode !== "none" && !active.length)} onClick={() => void prepare()}><SquarePen size={15} /> {working ? "Preparing…" : "Prepare in chat"}</button></footer>
  </Dialog.Content></Dialog.Portal></Dialog.Root>;
}

export function EnvironmentView({ item, packs, dependencyFingerprint, api, onPrepare, onError }: {
  item: CatalogItem; packs: CatalogItem[]; dependencyFingerprint?: string; api: StudioApi;
  onPrepare: (prompt: string) => Promise<void>; onError: (message: string) => void;
}) {
  const [report, setReport] = useState<EnvironmentReport | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const pickerTrigger = useRef<HTMLButtonElement>(null);
  const [picker, setPicker] = useState(false);
  const [viewer, setViewer] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    setReport(null); setLoading(true); setError("");
    void api.request<EnvironmentReport>(`/v1/scenarios/${item.id}/environment`, "GET", undefined, 180000).then((value) => { if (!cancelled) setReport(value); }).catch((failure) => { if (!cancelled) setError(String(failure)); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [api, item.id, item.source_sha256, dependencyFingerprint, refresh]);
  const sources = report ? [
    ...Object.entries(report.field_origins).map(([path, source]) => ({ path, source, layer: "Scenario" })),
    ...Object.entries(report.organization_model_origins).map(([path, source]) => ({ path, source, layer: "Organization" })),
    ...Object.entries(report.catalog_field_origins).map(([path, source]) => ({ path, source, layer: "Pack catalog" })),
  ].filter((entry) => `${entry.path} ${entry.source} ${entry.layer}`.toLowerCase().includes(query.toLowerCase())) : [];
  return <div className="workspace-content environment-view"><div className="section-heading"><div><h2>Environment</h2><p>Inspect exact pack versions, source declarations, and the resolved model before generating.</p></div><button className="icon-button" aria-label="Refresh environment" title="Read current scenario, packs, and overlays" disabled={loading} onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={17} className={loading ? "spinning" : ""} /></button></div>
    {loading && <p role="status" className="muted">Resolving environment…</p>}{error && <p role="alert" className="field-error">{error}</p>}
    {report && <><section className="surface"><div className="surface-heading"><h2><Layers3 size={17} /> Selected packs</h2><button ref={pickerTrigger} className="button-quiet" onClick={() => setPicker(true)}><SquarePen size={15} /> Choose packs</button></div>{!report.valid && <p role="alert" className="field-error">{report.error} Use Validation to review findings, or prepare a repair in chat.</p>}{report.source_sha256 !== item.source_sha256 && <p className="run-revision-note">The source changed during inspection. Refresh the library to load this revision.</p>}{report.selected_packs.length ? <ul className="environment-pack-list">{report.selected_packs.map((pack) => <li key={`${pack.source}:${pack.publisher}:${pack.type}:${pack.name}:${pack.version}`}><Check size={15} /><span><strong>{pack.name} <small>{pack.version}</small></strong><code>{packReference(pack)}</code><small>{pack.type} · {pack.publisher} · Digest {pack.digest.slice(0, 12)}</small></span></li>)}</ul> : <p className="muted">{report.valid ? "This scenario uses its inline environment and defaults; no packs are required." : "Selected packs could not be resolved."}</p>}</section>
    {report.valid && <><section className="surface"><div className="surface-heading"><h2>Resolved scenario model</h2><span className="eyebrow">{report.authored_kind}</span></div><p className="muted">Scenario fields after pack composition. Runtime catalogs also use the overlays listed below.</p><details className="environment-model"><summary>Inspect effective environment and baseline</summary><ChatMarkdown text={`\`\`\`json\n${JSON.stringify({ environment: report.effective_scenario.environment, baseline_activity: report.effective_scenario.baseline_activity }, null, 2)}\n\`\`\``} /></details></section>
    <section className="surface"><div className="surface-heading"><h2>Source declarations</h2><span className="eyebrow">TRACE VALUES</span></div><p className="muted">The files declaring scenario, organization, and pack fields. Overrides are explained below.</p><div className="search-box"><Search size={15} /><input aria-label="Search environment origins" placeholder="Search a field or declaring file…" value={query} onChange={(event) => setQuery(event.target.value)} /></div><div className="environment-origins"><table><thead><tr><th>Field</th><th>Layer</th><th>Declaring file</th></tr></thead><tbody>{sources.slice(0, 200).map((entry) => <tr key={`${entry.layer}:${entry.path}`}><td><code title={entry.path}>{entry.path}</code></td><td><span className="origin-layer">{entry.layer}</span></td><td><code title={entry.source}>{entry.source}</code></td></tr>)}</tbody></table>{!sources.length && <p className="muted">No matching declarations.</p>}{sources.length > 200 && <p className="muted">Showing 200 of {sources.length} declarations. Narrow the search to find a field.</p>}</div></section>
    <section className="surface"><div className="surface-heading"><h2>Overrides and precedence</h2></div><p className="environment-precedence">Defaults → industries → organization → workspace overlay → scenario</p>{report.merge_decisions.length ? <ul className="merge-decisions">{report.merge_decisions.map((decision, index) => <li key={index}><code>{decision.path}</code><span>{decision.action} · {decision.winner || decision.higher_layer}</span><small>{decision.lower_layer} → {decision.higher_layer}</small></li>)}</ul> : <p className="muted">No explicit overrides reported by the compiler.</p>}</section></>}
    <section className="surface"><div className="surface-heading"><h2>Workspace overlays</h2></div><p className="muted">These files apply to every scenario in this workspace. Project grouping currently does not change their scope.</p><div className="path-with-copy"><span className="path-value source-path">{report.overlay_root}</span><CopyPathButton path={report.overlay_root} label="Copy overlay path" onError={onError} /></div>{report.overlay_files.length ? <ul className="overlay-file-list">{report.overlay_files.map((file) => <li key={file.path}><button onClick={() => setViewer(file.path)}><FileCode2 size={15} /><span>{file.path}</span></button></li>)}</ul> : <p className="muted">No workspace overlays; packaged defaults apply.</p>}{report.overlays_truncated && <p className="muted">Only the first 500 overlay files are listed.</p>}</section>
    {picker && <PackPicker report={report} packs={packs} onClose={() => setPicker(false)} onPrepare={onPrepare} onError={onError} onReturnFocus={() => pickerTrigger.current?.focus()} />}
    {viewer && <BundleFileBrowser kind="environment" jobId={item.id} files={{ root: report.overlay_root, files: report.overlay_files.filter((file) => file.path === viewer), truncated: false }} api={api} onClose={() => setViewer(null)} onError={onError} />}</>}
  </div>;
}
