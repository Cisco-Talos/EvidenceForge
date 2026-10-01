import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, FolderOpen, Search } from "lucide-react";
import type { CatalogItem, StudioApi, StudioJob, StudioSnapshot } from "./api";
import { JobCard } from "./components";
import { chronologicalJobs } from "./jobOrder";

export function BundleLibrary({ snapshot, api, onError, onChanged, onOpenScenario }: {
  snapshot: StudioSnapshot; api: StudioApi; onError: (message: string) => void;
  onChanged: () => Promise<void>; onOpenScenario: (item: CatalogItem) => void;
}) {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [project, setProject] = useState("all");
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const [sizes, setSizes] = useState<Record<string, number | null>>({});
  const generations = snapshot.jobs.filter((job) => job.kind === "generation");
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
    const byPath = new Map<string, { name: string; item: CatalogItem | null; jobs: StudioJob[] }>();
    for (const job of generations) {
      const path = job.scenario || job.output_root;
      const item = snapshot.items.find((candidate) => candidate.kind === "scenario" && candidate.path === path) || null;
      const name = item?.name || path.split(/[\\/]/).slice(-2, -1)[0] || "Unavailable scenario";
      const group = byPath.get(path) || { name, item, jobs: [] };
      group.jobs.push(job);
      byPath.set(path, group);
    }
    return [...byPath.entries()].map(([path, group]) => ({ ...group, path,
      jobs: chronologicalJobs(group.jobs.filter((job) =>
        (status === "all" || (status === "complete" ? job.status === "completed" : job.status !== "completed")) &&
        `${group.name} ${job.id} ${job.output_root}`.toLowerCase().includes(search.trim().toLowerCase()))),
    })).filter((group) => group.jobs.length && (project === "all" || (project === "ungrouped" ? !group.item?.project_id : group.item?.project_id === project)))
      .sort((left, right) => left.name.localeCompare(right.name) || left.path.localeCompare(right.path));
  }, [generations, snapshot.items, search, status, project]);
  const visibleCount = groups.reduce((count, group) => count + group.jobs.length, 0);

  return <div className="page bundle-page"><div className="page-intro"><div><span className="eyebrow">GENERATED OUTPUT</span><h1>Bundles</h1><p>Inspect, export, and manage each Studio generation by scenario.</p></div></div>
    <div className="bundle-toolbar"><div className="search-box"><Search size={17} /><input aria-label="Search bundles" placeholder="Search scenarios or run IDs…" value={search} onChange={(event) => setSearch(event.target.value)} /></div><label>Status<select aria-label="Filter bundles by status" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">All statuses</option><option value="complete">Complete</option><option value="incomplete">Incomplete</option></select></label><label>Project<select aria-label="Filter bundles by project" value={project} onChange={(event) => setProject(event.target.value)}><option value="all">All projects</option><option value="ungrouped">Ungrouped</option>{snapshot.projects.map((entry) => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></label><span className="result-count">{visibleCount} {visibleCount === 1 ? "bundle" : "bundles"}</span></div>
    {groups.length ? <div className="bundle-groups">{groups.map((group) => <details className="bundle-group job-group" key={group.path} open={openGroups[group.path] ?? true} onToggle={(event) => { const open = event.currentTarget.open; setOpenGroups((current) => ({ ...current, [group.path]: open })); }}><summary><strong>{group.name}</strong><span>{group.jobs.length}</span>{group.jobs.some((job) => job.status !== "completed") && <small>{group.jobs.filter((job) => job.status !== "completed").length} incomplete</small>}</summary>{group.item && <div className="bundle-group-action"><button className="button-quiet" onClick={() => onOpenScenario(group.item!)}>Open scenario <ArrowUpRight size={15} /></button></div>}<div className="job-list">{group.jobs.map((job) => <JobCard key={job.id} job={job} name={group.name} grouped sizeBytes={sizes[job.id]} api={api} onError={onError} onChanged={onChanged} />)}</div></details>)}</div> : <div className="empty-panel"><FolderOpen size={28} /><h3>{generations.length ? "No matching bundles" : "No bundles yet"}</h3><p>{generations.length ? "Try another search or filter." : "Generate a scenario to create its first bundle."}</p></div>}
  </div>;
}
