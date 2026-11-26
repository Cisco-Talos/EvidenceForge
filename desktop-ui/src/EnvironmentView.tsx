import { CatalogObjectMenu } from "./CatalogObjectMenu";
import { ActionShortcut, ObjectMenu, type ObjectAction } from "./ObjectActions";
import { useRef, useState } from "react";
import { ArrowUpRight, Check } from "lucide-react";
import type { CatalogItem, DependencyHealth, StudioApi } from "./api";
import { AssetBrowser } from "./AssetBrowser";
import { ConfigurationLayers } from "./ConfigurationLayers";
import { ChatMarkdown } from "./ChatMarkdown";
import { SourceDeclarations } from "./SourceDeclarations";
import { InspectionSection } from "./InspectionSection";
import { DependencyRows } from "./ImportDialog";
import { dependencyPackItem, selectedPackItem } from "./environmentPackLinks";
import { PackPicker, packReference } from "./PackPicker";
import { RequestFeedback } from "./RequestFeedback";
import type { useEnvironmentInspection } from "./useEnvironmentInspection";

export function EnvironmentView({ item, packs, dependencyHealth, inspection, onImportPacks, onOpenPack, onChanged, api, onPrepare, onPreparePacks, onError, embedded = false }: {
  item: CatalogItem; packs: CatalogItem[]; dependencyHealth?: DependencyHealth;
  inspection: ReturnType<typeof useEnvironmentInspection>;
  onImportPacks?: () => void; onChanged?: () => Promise<void>; api: StudioApi;
  onOpenPack?: (pack: CatalogItem) => void;
  onPrepare: (prompt: string) => Promise<void>; onPreparePacks: (prompt: string) => Promise<void>; onError: (message: string) => void; embedded?: boolean;
}) {
  const { report, pending: loading, error, completedAt, requestKey, refresh } = inspection;
  const pickerTrigger = useRef<HTMLButtonElement>(null);
  const [picker, setPicker] = useState(false);
  const packRows = dependencyHealth?.rows.filter((row) => row.kind === "pack") || [];
  const otherRows = dependencyHealth?.rows.filter((row) => row.kind !== "pack") || [];
  const fileErrors = otherRows.filter((row) => ["missing", "conflict"].includes(row.status));
  const packCount = packRows.length || report?.selected_packs.length || 0;
  const refreshAction: ObjectAction = { id: "refresh", label: "Refresh environment", group: "work", disabled: loading, reason: "Environment is refreshing", run: refresh };
  const packActions: ObjectAction[] = [
    { id: "choose", label: "Choose packs…", group: "work", disabled: !report || loading, reason: "Wait for the environment inspection", run: () => setPicker(true) },
    ...(onImportPacks ? [{ id: "import", label: "Import packs…", group: "manage" as const, run: onImportPacks }] : []),
  ];
  return <div className="workspace-content environment-view">
    {!embedded && <div className="section-heading"><h2>Environment</h2><ActionShortcut action={refreshAction} /></div>}
    <section className="environment-direct-packs" aria-label="Environment packs">
      <header><h3>Packs <small>{packCount}</small></h3>{onImportPacks && packRows.some((row) => ["missing", "conflict"].includes(row.status)) && <ActionShortcut action={packActions[1]} />}<button ref={pickerTrigger} className="button-quiet" disabled={!report || loading} onClick={() => setPicker(true)}>Choose packs…</button><ObjectMenu label="Environment pack actions" actions={packActions} /></header>
      {packRows.length ? <DependencyRows rows={packRows} renderActions={(row) => { const target = dependencyPackItem(row, report?.selected_packs || [], packs); return target ? <CatalogObjectMenu item={target} fallbackActions={[{ id: "open", label: "Open", group: "inspect", disabled: !onOpenPack, reason: "Pack workspace unavailable", run: () => onOpenPack?.(target) }]} /> : null; }} canOpen={(row) => !!onOpenPack && !!dependencyPackItem(row, report?.selected_packs || [], packs)} onOpen={(row) => { const target = dependencyPackItem(row, report?.selected_packs || [], packs); if (target) onOpenPack?.(target); }} /> : report?.selected_packs.length ? <ul className="environment-pack-list">{report.selected_packs.map((pack) => {
        const target = selectedPackItem(pack, packs);
        const title = <strong>{pack.name} <small>{pack.version}</small></strong>;
        return <li key={`${pack.source}:${pack.publisher}:${pack.type}:${pack.name}:${pack.version}`}><Check size={15} /><span>{target && onOpenPack ? <button type="button" className="environment-pack-link" aria-label={`Open ${pack.publisher}:${pack.type}:${pack.name}@${pack.version} pack workspace`} title="Open pack workspace" onClick={() => onOpenPack(target)}>{title}<ArrowUpRight size={14} aria-hidden="true" /></button> : title}<code>{packReference(pack)}</code><small>{pack.type} · {pack.publisher} · Digest {pack.digest.slice(0, 12)}</small></span>{target && <CatalogObjectMenu item={target} fallbackActions={[{ id: "open", label: "Open", group: "inspect", disabled: !onOpenPack, reason: "Pack workspace unavailable", run: () => onOpenPack?.(target) }]} />}</li>;
      })}</ul> : report && <p className="muted">{report.valid ? "This scenario uses its inline environment; no packs are selected." : "Selected packs could not be resolved."}</p>}
      {fileErrors.length > 0 && <div className="environment-file-errors"><h3>Files needing attention</h3><DependencyRows rows={fileErrors} /></div>}
      {otherRows.length > fileErrors.length && <InspectionSection title="Included files and dependencies" count={`${otherRows.length - fileErrors.length} checks`}><DependencyRows rows={otherRows.filter((row) => !fileErrors.includes(row))} /></InspectionSection>}
    </section>
    {!embedded && <RequestFeedback pending={loading} label="Resolving environment…" error={error} completedAt={completedAt} completedLabel="Checked" />}
    {report && <>
      {!report.valid && <p role="alert" className="field-error">{report.error} Use Validation to review findings, or prepare a repair in chat.</p>}
      {report.source_sha256 !== item.source_sha256 && <p className="run-revision-note">The source changed during inspection. Refresh the library to load this revision.</p>}
      {report.valid && <AssetBrowser key={item.id} item={item} api={api} refreshVersion={requestKey} onChanged={async () => { refresh(); await onChanged?.(); }} />}
      <ConfigurationLayers item={item} report={report} api={api} onRefresh={refresh} onPrepare={onPrepare} onError={onError} />
      {report.valid && <>
        <InspectionSection title="Resolved scenario model" count={report.authored_kind} summary={(() => { const environment = report.effective_scenario.environment as Record<string, unknown> | undefined; return ["users", "systems", "groups"].map((key) => Array.isArray(environment?.[key]) ? `${environment[key].length} ${environment[key].length === 1 ? key.slice(0, -1) : key}` : "").filter(Boolean).join(" · ") || "No environment entities"; })()}><p className="muted">Scenario fields after pack composition. Runtime catalogs also use the selected configuration layers.</p><ChatMarkdown text={"```json\n" + JSON.stringify({ environment: report.effective_scenario.environment, baseline_activity: report.effective_scenario.baseline_activity }, null, 2) + "\n```"} /></InspectionSection>
        <SourceDeclarations key={item.id} item={item} report={report} api={api} onError={onError} />
        <InspectionSection title="Overrides and precedence" count={`${report.merge_decisions.length} override${report.merge_decisions.length === 1 ? "" : "s"}`} summary={report.merge_decisions.slice(0, 2).map((decision) => `${decision.path} → ${decision.winner || decision.higher_layer}`).join(" · ") || "No explicit overrides"}><p className="environment-precedence">Defaults → industries → organization → workspace overlay{report.configuration?.scopes.filter((scope) => scope.id !== "workspace" && scope.enabled).map((scope) => ` → ${scope.name}`).join("")} → scenario fields</p>{report.merge_decisions.length ? <ul className="merge-decisions">{report.merge_decisions.map((decision, index) => <li key={index}><code>{decision.path}</code><span>{decision.action} · {decision.winner || decision.higher_layer}</span><small>{decision.lower_layer} → {decision.higher_layer}</small></li>)}</ul> : <p className="muted">No explicit overrides reported by the compiler.</p>}</InspectionSection>
      </>}
      {picker && <PackPicker
        api={api} targetId={item.id} currentPacks={report.selected_packs} packs={packs}
        onClose={() => setPicker(false)} onPrepare={onPreparePacks}
        onApplied={async () => { refresh(); await onChanged?.(); }}
        onReturnFocus={() => pickerTrigger.current?.focus()}
      />}
    </>}
  </div>;
}
