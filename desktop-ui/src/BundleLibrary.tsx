import { useEffect, useMemo, useRef, useState } from "react";
import { BundlePropertiesDialog } from "./ArtifactProperties";
import { isTauri, invoke } from "@tauri-apps/api/core";
import { ChevronRight, ChevronDown, FolderOpen, FolderPlus, Search } from "lucide-react";
import type { CatalogItem, ImportedBundle, StudioApi, StudioSnapshot } from "./api";
import { BundleFileBrowser, type BundleFiles } from "./BundleFileBrowser";
import { ActionShortcut, ObjectMenu, RemovalConfirmation, type ObjectAction } from "./ObjectActions";
import { CopyPathButton, writePathToClipboard } from "./CopyPathButton";
import { ExportStatus } from "./ExportStatus";
import { BundleOptionsMenu, formatBundleSize, formatTime, JobCard, StatusBadge } from "./components";
import { bundleSummary, orderedBundles } from "./workspaceSummaries";
import { HeaderSummary } from "./WorkspaceSection";
import { capturedVersion, groupBundles, type BundleGroup } from "./bundleGrouping";

export function ImportedBundleRow({ bundle, api, onError, onChanged }: {
  bundle: ImportedBundle; api: StudioApi; onError: (message: string) => void; onChanged: () => Promise<void>;
}) {
  const row = useRef<HTMLDetailsElement>(null);
  const [propertiesOpen, setPropertiesOpen] = useState(false);
  const [files, setFiles] = useState<BundleFiles | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [working, setWorking] = useState(false);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [exportProgress, setExportProgress] = useState<{ id: string; bytes: number; total: number | null } | null>(null);
  const folderName = bundle.root.split(/[\\/]/).filter(Boolean).slice(-1)[0] || bundle.scenario_name;
  async function openFiles() {
    try { setFiles(await api.request<BundleFiles>(`/v1/bundles/${bundle.id}/files`)); }
    catch (error) { onError(String(error)); }
  }
  async function exportZip() {
    if (working) return;
    if (row.current) row.current.open = true;
    setWorking(true);
    setSavedPath(null);
    try {
      const result = await api.download(`/v1/bundles/${bundle.id}/bundle.zip`, `${bundle.scenario_name.replace(/[^a-z0-9._-]+/gi, "-")}-${bundle.id.slice(0, 8)}.zip`, setExportProgress);
      if (result.status === "saved") setSavedPath(result.path);
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); setExportProgress(null); }
  }
  async function remove() {
    setWorking(true);
    try {
      await api.request(`/v1/bundles/${bundle.id}`, "DELETE");
      await onChanged();
      setConfirmRemove(false);
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); }
  }
  const actions: ObjectAction[] = [
    { id: "open", label: "Open details", group: "inspect", run: () => { if (row.current) row.current.open = true; } },
    { id: "properties", label: "Properties…", group: "inspect", run: () => setPropertiesOpen(true) },
    { id: "files", label: "View files", group: "inspect", run: openFiles },
    { id: "export", label: "Export ZIP…", group: "reuse", disabled: working, reason: "An operation is in progress", run: exportZip },
    { id: "copy", label: "Copy path", group: "reuse", run: () => writePathToClipboard(bundle.root).catch((error) => onError(String(error))) },
    { id: "remove", label: "Remove from Studio", group: "remove", disabled: working, reason: "An operation is in progress", description: "Keep external files in their original location", run: () => setConfirmRemove(true) },
  ];
  return <details ref={row} className="job-row imported-bundle-row" id={`bundle-${bundle.id}`}>
    <summary className="job-row-summary"><span className="job-row-name"><span className="job-row-title"><strong title={bundle.root}>{folderName}</strong><span className="scenario-version" title="Scenario identity captured by this bundle">{capturedVersion(bundle.scenario_source)}</span><span className="bundle-size">{formatBundleSize(bundle.size_bytes)}</span></span><small>Imported CLI or earlier desktop bundle</small></span><time className="job-row-time">{formatTime(bundle.created_at)}</time><StatusBadge status="Completed" /><span className="job-row-result">Read-only in Studio</span><span className="job-row-controls"><span className="job-row-shortcuts"><ActionShortcut action={actions[2]} /><ActionShortcut action={actions[3]} /></span><ChevronDown size={16} className="job-row-chevron" /><BundleOptionsMenu id={bundle.id} onProperties={() => setPropertiesOpen(true)} actions={actions} /></span></summary>
    <div className="job-row-details"><div className="path-with-copy job-output-path"><span className="path-value muted" title={bundle.root}>{bundle.root}</span><CopyPathButton path={bundle.root} label="Copy bundle path" onError={onError} /></div><p className="muted small">Studio did not create this bundle. Removing it from the library leaves its files on disk.</p>{working && isTauri() && <ExportStatus progress={exportProgress} api={api} onError={onError} />}{savedPath && <div className="path-with-copy muted small"><span className="path-value">Saved to {savedPath}</span><CopyPathButton path={savedPath} label="Copy saved ZIP path" onError={onError} /></div>}</div>
    {propertiesOpen && <BundlePropertiesDialog id={bundle.id} imported api={api} onClose={() => setPropertiesOpen(false)} />}
    {files && <BundleFileBrowser jobId={bundle.id} kind="bundles" files={files} api={api} onClose={() => setFiles(null)} onError={onError} />}
    {confirmRemove && <RemovalConfirmation title="Remove from Studio?" label="Remove from Studio" busy={working} onCancel={() => setConfirmRemove(false)} onConfirm={remove}><p>This bundle disappears from the library. Its files remain at their current path and can be imported again.</p></RemovalConfirmation>}
  </details>;
}

function BundleGroupRow({ group, snapshot, sizes, api, onError, onChanged, onOpenScenario, disambiguate }: {
  group: BundleGroup; snapshot: StudioSnapshot; sizes: Record<string, number | null>; api: StudioApi;
  onError: (message: string) => void; onChanged: () => Promise<void>; onOpenScenario: (item: CatalogItem) => void; disambiguate: boolean;
}) {
  const row = useRef<HTMLDetailsElement>(null);
  function expand(mode: "latest" | "all" | "none") {
    if (row.current) row.current.open = mode !== "none";
    const runs = row.current?.querySelectorAll<HTMLDetailsElement>(".job-list > .job-row");
    runs?.forEach((entry, index) => { entry.open = mode === "all" || (mode === "latest" && index === 0); });
    if (mode === "latest") runs?.[0]?.querySelector<HTMLElement>("summary")?.focus();
  }
  const sourceActions: ObjectAction[] = group.items.map((item) => ({ id: item.id, label: snapshot.artifact_groups?.[item.id]?.published_version ? `v${snapshot.artifact_groups[item.id].published_version}` : item.version === "Draft" ? "Draft" : "Legacy scenario", group: "inspect", run: () => onOpenScenario(item) }));
  const actions: ObjectAction[] = [
    { id: "latest", label: "Open latest run", group: "inspect", run: () => expand("latest") },
    { id: "expand", label: "Expand all runs", group: "inspect", run: () => expand("all") },
    { id: "collapse", label: "Collapse all runs", group: "inspect", run: () => expand("none") },
    { id: "scenario", label: "Open scenario", group: "inspect", disabled: !sourceActions.length, reason: "The original scenario is no longer in the library", ...(sourceActions.length > 1 ? { children: sourceActions } : { run: sourceActions[0]?.run }) },
  ];
  return <details ref={row} className="bundle-group job-group">
    <summary><ChevronRight size={17} className="disclosure-chevron" /><strong>{group.name}{disambiguate && group.publisher && <small className="bundle-publisher">{group.publisher}</small>}</strong><span>{group.jobs.length + group.imports.length}</span><small className="group-summary"><HeaderSummary summary={bundleSummary(group.jobs, group.imports, sizes)} /></small><ObjectMenu label={`Bundle group actions for ${group.name}${disambiguate ? ` (${group.publisher || "unassigned"})` : ""}`} actions={actions} /></summary>
    <div className="job-list">{orderedBundles(group.jobs, group.imports).map((entry) => entry.kind === "job"
      ? <JobCard key={entry.id} job={entry.job} name={group.name} grouped sourceLabel={capturedVersion(entry.job.scenario_source)} sizeBytes={sizes[entry.id]} api={api} onError={onError} onChanged={onChanged} />
      : <ImportedBundleRow key={entry.id} bundle={entry.bundle} api={api} onError={onError} onChanged={onChanged} />)}</div>
  </details>;
}

export function BundleLibrary({ snapshot, api, onError, onChanged, onOpenScenario }: {
  snapshot: StudioSnapshot; api: StudioApi; onError: (message: string) => void;
  onChanged: () => Promise<void>; onOpenScenario: (item: CatalogItem) => void;
}) {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [project, setProject] = useState("all");
  const [sizes, setSizes] = useState<Record<string, number | null>>({});
  const [importPath, setImportPath] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const generations = snapshot.jobs.filter((job) => job.kind === "generation");
  const imports = snapshot.imported_bundles || [];
  const sizeKey = generations.map((job) => `${job.id}:${job.status}`).sort().join("|");
  const hasActiveGeneration = generations.some((job) => job.status === "running");
  useEffect(() => {
    let active = true;
    async function refreshSizes() {
      try {
        const next = await api.request<Record<string, number | null>>("/v1/jobs/bundle-sizes");
        if (active) setSizes(next);
      } catch (error) { if (active) onError(String(error)); }
    }
    void refreshSizes();
    const timer = hasActiveGeneration ? setInterval(() => void refreshSizes(), 15000) : null;
    return () => { active = false; if (timer) clearInterval(timer); };
  }, [api, onError, sizeKey, hasActiveGeneration]);
  const groups = useMemo(() => {
    const term = search.trim().toLowerCase();
    const inProject = (group: BundleGroup, id: string) => project === "all" || (project === "ungrouped" ? !group.owners[id]?.project_id : group.owners[id]?.project_id === project);
    return groupBundles(snapshot).map((group) => ({ ...group,
      jobs: group.jobs.filter((job) => inProject(group, job.id) &&
        (status === "all" || (status === "complete" ? job.status === "completed" : job.status !== "completed")) &&
        `${group.name} ${group.publisher || ""} ${job.id} ${job.output_root} ${capturedVersion(job.scenario_source)}`.toLowerCase().includes(term)),
      imports: status === "incomplete" ? [] : group.imports.filter((bundle) => inProject(group, bundle.id) &&
        `${group.name} ${group.publisher || ""} ${bundle.id} ${bundle.root} ${capturedVersion(bundle.scenario_source)}`.toLowerCase().includes(term)),
    })).filter((group) => group.jobs.length || group.imports.length)
      .sort((left, right) => (orderedBundles(right.jobs, right.imports)[0]?.time || 0) - (orderedBundles(left.jobs, left.imports)[0]?.time || 0) || left.name.localeCompare(right.name) || left.key.localeCompare(right.key));
  }, [snapshot.jobs, snapshot.imported_bundles, snapshot.items, snapshot.source_paths, snapshot.artifact_groups, search, status, project]);
  const visibleCount = groups.reduce((count, group) => count + group.jobs.length + group.imports.length, 0);
  async function importBundle() {
    if (!importPath?.trim()) return;
    setWorking(true);
    try {
      await api.request("/v1/bundles/import", "POST", { path: importPath.trim() });
      await onChanged();
      setImportPath(null);
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); }
  }
  async function discover() {
    setWorking(true);
    try {
      const result = await api.request<{ imported: number }>("/v1/bundles/discover", "POST");
      await onChanged();
      onError(result.imported ? `Found ${result.imported} complete bundle${result.imported === 1 ? "" : "s"} in this workspace.` : "No additional complete bundles found under workspace runs.");
    } catch (error) { onError(String(error)); }
    finally { setWorking(false); }
  }
  async function chooseFolder() {
    try {
      const chosen = await invoke<string | null>("choose_bundle_folder");
      if (chosen) setImportPath(chosen);
    } catch (error) { onError(String(error)); }
  }

  return <div className="page bundle-page"><div className="page-intro"><div><span className="eyebrow">GENERATED OUTPUT</span><h1>Bundles</h1><p>Inspect, export, and manage Studio runs and imported CLI bundles.</p></div><div className="bundle-page-actions"><button className="button-quiet" disabled={working} onClick={() => void discover()}><Search size={16} /> Find in workspace</button><button className="button-primary" onClick={() => setImportPath("")}><FolderPlus size={17} /> Import bundle</button></div></div>
    <div className="bundle-toolbar"><div className="search-box"><Search size={17} /><input aria-label="Search bundles" placeholder="Search scenarios or run IDs…" value={search} onChange={(event) => setSearch(event.target.value)} /></div><label>Status<select aria-label="Filter bundles by status" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">All statuses</option><option value="complete">Complete</option><option value="incomplete">Incomplete</option></select></label><label>Project<select aria-label="Filter bundles by project" value={project} onChange={(event) => setProject(event.target.value)}><option value="all">All projects</option><option value="ungrouped">Ungrouped</option>{snapshot.projects.map((entry) => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></label><span className="result-count">{visibleCount} {visibleCount === 1 ? "bundle" : "bundles"}</span></div>
    {groups.length ? <div className="bundle-groups">{groups.map((group) => <BundleGroupRow key={group.key} group={group} snapshot={snapshot} sizes={sizes} api={api} onError={onError} onChanged={onChanged} onOpenScenario={onOpenScenario} disambiguate={groups.filter((entry) => entry.name === group.name).length > 1} />)}</div> : <div className="empty-panel"><FolderOpen size={28} /><h3>{generations.length + imports.length ? "No matching bundles" : "No bundles yet"}</h3><p>{generations.length + imports.length ? "Try another search or filter." : "Generate a scenario or import an existing bundle."}</p></div>}
    {importPath !== null && <div className="modal-backdrop"><form className="close-modal" role="dialog" aria-modal="true" aria-label="Import bundle" onSubmit={(event) => { event.preventDefault(); void importBundle(); }}><h2>Import an existing bundle</h2><p>Choose a complete EvidenceForge generation folder. Studio indexes it for viewing and export; its files remain where they are.</p><label className="modal-field">Bundle folder<input autoFocus aria-label="Bundle folder" name="bundle-folder" autoComplete="off" value={importPath} onChange={(event) => setImportPath(event.target.value)} /></label>{isTauri() && <button type="button" className="button-quiet" onClick={() => void chooseFolder()}><FolderOpen size={16} /> Browse…</button>}<div className="close-modal-actions"><button type="button" className="button-quiet" disabled={working} onClick={() => setImportPath(null)}>Cancel</button><button type="submit" className="button-primary" disabled={working || !importPath.trim()}>{working ? "Importing…" : "Import bundle"}</button></div></form></div>}
  </div>;
}
