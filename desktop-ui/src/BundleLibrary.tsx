import { useEffect, useMemo, useState } from "react";
import { isTauri, invoke } from "@tauri-apps/api/core";
import { ArrowUpRight, ChevronRight, ChevronDown, Download, FolderOpen, FolderPlus, Search, Trash2 } from "lucide-react";
import type { CatalogItem, ImportedBundle, StudioApi, StudioJob, StudioSnapshot } from "./api";
import { BundleFileBrowser, type BundleFiles } from "./BundleFileBrowser";
import { CopyPathButton } from "./CopyPathButton";
import { ExportStatus } from "./ExportStatus";
import { formatBundleSize, formatTime, JobCard, StatusBadge } from "./components";
import { chronologicalJobs } from "./jobOrder";
import { bundleSummary, orderedBundles } from "./workspaceSummaries";
import { HeaderSummary } from "./WorkspaceSection";

export function ImportedBundleRow({ bundle, api, onError, onChanged }: {
  bundle: ImportedBundle; api: StudioApi; onError: (message: string) => void; onChanged: () => Promise<void>;
}) {
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
  return <details className="job-row imported-bundle-row" id={`bundle-${bundle.id}`}>
    <summary className="job-row-summary"><span className="job-row-name"><span className="job-row-title"><strong title={bundle.root}>{folderName}</strong><span className="bundle-size">{formatBundleSize(bundle.size_bytes)}</span></span><small>Imported CLI or earlier desktop bundle</small></span><time className="job-row-time">{formatTime(bundle.created_at)}</time><StatusBadge status="Completed" /><span className="job-row-result">Read-only in Studio</span><ChevronDown size={16} className="job-row-chevron" /></summary>
    <div className="job-row-details"><div className="path-with-copy job-output-path"><span className="path-value muted" title={bundle.root}>{bundle.root}</span><CopyPathButton path={bundle.root} label="Copy bundle path" onError={onError} /></div><p className="muted small">Studio did not create this bundle. Removing it from the library leaves its files on disk.</p><div className="job-actions"><button className="button-quiet" onClick={() => void openFiles()}><FolderOpen size={16} /> View files</button><button className="button-quiet" disabled={working} onClick={() => void exportZip()}><Download size={16} /> {working ? "Exporting…" : isTauri() ? "Export ZIP" : "Download ZIP"}</button><button className="button-quiet" disabled={working} onClick={() => setConfirmRemove(true)}><Trash2 size={16} /> Remove from Studio</button></div>{working && isTauri() && <ExportStatus progress={exportProgress} api={api} onError={onError} />}{savedPath && <div className="path-with-copy muted small"><span className="path-value">Saved to {savedPath}</span><CopyPathButton path={savedPath} label="Copy saved ZIP path" onError={onError} /></div>}</div>
    {files && <BundleFileBrowser jobId={bundle.id} kind="bundles" files={files} api={api} onClose={() => setFiles(null)} onError={onError} />}
    {confirmRemove && <div className="modal-backdrop"><div className="close-modal" role="dialog" aria-modal="true" aria-label="Remove imported bundle"><h2>Remove from Studio?</h2><p>This bundle will disappear from the library. Its files remain at their current path and can be imported again.</p><div className="close-modal-actions"><button className="button-quiet" onClick={() => setConfirmRemove(false)}>Cancel</button><button className="button-danger" disabled={working} onClick={() => void remove()}>Remove from Studio</button></div></div></div>}
  </details>;
}

export function BundleLibrary({ snapshot, api, onError, onChanged, onOpenScenario }: {
  snapshot: StudioSnapshot; api: StudioApi; onError: (message: string) => void;
  onChanged: () => Promise<void>; onOpenScenario: (item: CatalogItem) => void;
}) {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [project, setProject] = useState("all");
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
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
    const byPath = new Map<string, { name: string; item: CatalogItem | null; jobs: StudioJob[]; imports: ImportedBundle[] }>();
    for (const job of generations) {
      const path = job.scenario || job.output_root;
      const item = snapshot.items.find((candidate) => candidate.kind === "scenario" && candidate.path === path) || null;
      const name = item?.name || path.split(/[\\/]/).slice(-2, -1)[0] || "Unavailable scenario";
      const group = byPath.get(path) || { name, item, jobs: [], imports: [] };
      group.jobs.push(job);
      byPath.set(path, group);
    }
    for (const bundle of imports) {
      const matches = snapshot.items.filter((item) => item.kind === "scenario" && item.name === bundle.scenario_name);
      const item = matches.length === 1 ? matches[0] : null;
      const path = item?.path || `imported:${bundle.scenario_name}`;
      const group = byPath.get(path) || { name: bundle.scenario_name, item, jobs: [], imports: [] };
      group.imports.push(bundle);
      byPath.set(path, group);
    }
    const term = search.trim().toLowerCase();
    return [...byPath.entries()].map(([path, group]) => ({ ...group, path,
      jobs: chronologicalJobs(group.jobs.filter((job) =>
        (status === "all" || (status === "complete" ? job.status === "completed" : job.status !== "completed")) &&
        `${group.name} ${job.id} ${job.output_root}`.toLowerCase().includes(term))),
      imports: status === "incomplete" ? [] : group.imports.filter((bundle) =>
        `${group.name} ${bundle.id} ${bundle.root}`.toLowerCase().includes(term)),
    })).filter((group) => (group.jobs.length || group.imports.length) && (project === "all" || (project === "ungrouped" ? !group.item?.project_id : group.item?.project_id === project)))
      .sort((left, right) => left.name.localeCompare(right.name) || left.path.localeCompare(right.path));
  }, [generations, imports, snapshot.items, search, status, project]);
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
    {groups.length ? <div className="bundle-groups">{groups.map((group) => <details className="bundle-group job-group" key={group.path} open={openGroups[group.path] ?? false} onToggle={(event) => { const open = event.currentTarget.open; setOpenGroups((current) => ({ ...current, [group.path]: open })); }}><summary><ChevronRight size={17} className="disclosure-chevron" /><strong>{group.name}</strong><span>{group.jobs.length + group.imports.length}</span><small className="group-summary"><HeaderSummary summary={bundleSummary(group.jobs, group.imports, sizes)} /></small></summary>{group.item && <div className="bundle-group-action"><button className="button-quiet" onClick={() => onOpenScenario(group.item!)}>Open scenario <ArrowUpRight size={15} /></button></div>}<div className="job-list">{orderedBundles(group.jobs, group.imports).map((entry) => entry.kind === "job" ? <JobCard key={entry.id} job={entry.job} name={group.name} grouped sizeBytes={sizes[entry.id]} api={api} onError={onError} onChanged={onChanged} /> : <ImportedBundleRow key={entry.id} bundle={entry.bundle} api={api} onError={onError} onChanged={onChanged} />)}</div></details>)}</div> : <div className="empty-panel"><FolderOpen size={28} /><h3>{generations.length + imports.length ? "No matching bundles" : "No bundles yet"}</h3><p>{generations.length + imports.length ? "Try another search or filter." : "Generate a scenario or import an existing bundle."}</p></div>}
    {importPath !== null && <div className="modal-backdrop"><form className="close-modal" role="dialog" aria-modal="true" aria-label="Import bundle" onSubmit={(event) => { event.preventDefault(); void importBundle(); }}><h2>Import an existing bundle</h2><p>Choose a complete EvidenceForge generation folder. Studio indexes it for viewing and export; its files remain where they are.</p><label className="modal-field">Bundle folder<input autoFocus aria-label="Bundle folder" name="bundle-folder" autoComplete="off" value={importPath} onChange={(event) => setImportPath(event.target.value)} /></label>{isTauri() && <button type="button" className="button-quiet" onClick={() => void chooseFolder()}><FolderOpen size={16} /> Browse…</button>}<div className="close-modal-actions"><button type="button" className="button-quiet" disabled={working} onClick={() => setImportPath(null)}>Cancel</button><button type="submit" className="button-primary" disabled={working || !importPath.trim()}>{working ? "Importing…" : "Import bundle"}</button></div></form></div>}
  </div>;
}
