import { useEffect, useRef, useState } from "react";
import { Check, RefreshCw, Search, SquarePen } from "lucide-react";
import { Dialog } from "radix-ui";
import type { CatalogItem, EnvironmentReport, SelectedPack, StudioApi } from "./api";
import { ConfigurationLayers } from "./ConfigurationLayers";
import { ChatMarkdown } from "./ChatMarkdown";
import { SourceDeclarations } from "./SourceDeclarations";
import { InspectionSection } from "./InspectionSection";

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

export function EnvironmentView({ item, packs, dependencyFingerprint, api, onPrepare, onError, embedded = false }: {
  item: CatalogItem; packs: CatalogItem[]; dependencyFingerprint?: string; api: StudioApi;
  onPrepare: (prompt: string) => Promise<void>; onError: (message: string) => void; embedded?: boolean;
}) {
  const [report, setReport] = useState<EnvironmentReport | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const pickerTrigger = useRef<HTMLButtonElement>(null);
  const [picker, setPicker] = useState(false);
  useEffect(() => {
    let cancelled = false;
    setReport(null); setLoading(true); setError("");
    void api.request<EnvironmentReport>(`/v1/scenarios/${item.id}/environment`, "GET", undefined, 180000).then((value) => { if (!cancelled) setReport(value); }).catch((failure) => { if (!cancelled) setError(String(failure)); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [api, item.id, item.source_sha256, dependencyFingerprint, refresh]);
  return <div className="workspace-content environment-view"><div className="section-heading"><div>{!embedded && <h2>Environment</h2>}<p>Inspect exact pack versions, source declarations, and the resolved model before generating.</p></div><button className="icon-button" aria-label="Refresh environment" title="Read current scenario, packs, and overlays" disabled={loading} onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={17} className={loading ? "spinning" : ""} /></button></div>
    {loading && <p role="status" className="muted">Resolving environment…</p>}{error && <p role="alert" className="field-error">{error}</p>}
    {report && <>{!report.valid && <p role="alert" className="field-error">{report.error} Use Validation to review findings, or prepare a repair in chat.</p>}{report.source_sha256 !== item.source_sha256 && <p className="run-revision-note">The source changed during inspection. Refresh the library to load this revision.</p>}<InspectionSection title="Selected packs" count={`${report.selected_packs.length} pack${report.selected_packs.length === 1 ? "" : "s"}`} actions={<button ref={pickerTrigger} className="button-quiet" onClick={() => setPicker(true)}><SquarePen size={15} /> Choose packs</button>}>{report.selected_packs.length ? <ul className="environment-pack-list">{report.selected_packs.map((pack) => <li key={`${pack.source}:${pack.publisher}:${pack.type}:${pack.name}:${pack.version}`}><Check size={15} /><span><strong>{pack.name} <small>{pack.version}</small></strong><code>{packReference(pack)}</code><small>{pack.type} · {pack.publisher} · Digest {pack.digest.slice(0, 12)}</small></span></li>)}</ul> : <p className="muted">{report.valid ? "This scenario uses its inline environment and defaults; no packs are required." : "Selected packs could not be resolved."}</p>}</InspectionSection>
    <ConfigurationLayers item={item} report={report} api={api} onRefresh={() => setRefresh((value) => value + 1)} onPrepare={onPrepare} onError={onError} />
    {report.valid && <><InspectionSection title="Resolved scenario model" count={report.authored_kind}><p className="muted">Scenario fields after pack composition. Runtime catalogs also use the selected configuration layers.</p><ChatMarkdown text={`\`\`\`json\n${JSON.stringify({ environment: report.effective_scenario.environment, baseline_activity: report.effective_scenario.baseline_activity }, null, 2)}\n\`\`\``} /></InspectionSection>
    <SourceDeclarations key={item.id} item={item} report={report} api={api} onError={onError} />
    <InspectionSection title="Overrides and precedence" count={`${report.merge_decisions.length} override${report.merge_decisions.length === 1 ? "" : "s"}`}><p className="environment-precedence">Defaults → industries → organization → workspace overlay{report.configuration?.scopes.filter((scope) => scope.id !== "workspace" && scope.enabled).map((scope) => ` → ${scope.name}`).join("")} → scenario fields</p>{report.merge_decisions.length ? <ul className="merge-decisions">{report.merge_decisions.map((decision, index) => <li key={index}><code>{decision.path}</code><span>{decision.action} · {decision.winner || decision.higher_layer}</span><small>{decision.lower_layer} → {decision.higher_layer}</small></li>)}</ul> : <p className="muted">No explicit overrides reported by the compiler.</p>}</InspectionSection></>}
    {picker && <PackPicker report={report} packs={packs} onClose={() => setPicker(false)} onPrepare={onPrepare} onError={onError} onReturnFocus={() => pickerTrigger.current?.focus()} />}
</>}
  </div>;
}
