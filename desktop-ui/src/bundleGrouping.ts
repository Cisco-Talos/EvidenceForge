import type { CapturedScenario, CatalogItem, ImportedBundle, StudioJob, StudioSnapshot } from "./api";
import { artifactGroup } from "./artifactGrouping";
import { artifactTitle } from "./artifactNaming";
import { belongsToScenario } from "./scenarioSources";

export interface BundleGroup {
  key: string;
  name: string;
  publisher: string | null;
  items: CatalogItem[];
  jobs: StudioJob[];
  imports: ImportedBundle[];
  owners: Record<string, CatalogItem | null>;
}

export function capturedVersion(source?: CapturedScenario | null): string {
  if (source?.status === "published" && source.version) return `v${source.version}`;
  if (source?.status === "draft") return "Draft";
  if (source?.status === "legacy") return "Legacy scenario";
  return "Version unknown";
}

/** Group known versions through file-owned lineage and relocated paths, never names alone. */
export function groupBundles(snapshot: StudioSnapshot): BundleGroup[] {
  const scenarios = snapshot.items.filter((item) => item.kind === "scenario");
  const groups = new Map<string, BundleGroup>();
  function matchingSource(source: CapturedScenario | null | undefined, name?: string): CatalogItem | null {
    if (source?.status === "draft" && !source.publisher) return null;
    const candidates = scenarios.filter((item) => item.name === (source?.name || name)
      && (!source?.publisher || artifactGroup(item, snapshot.artifact_groups).publisher === source.publisher));
    const families = new Set(candidates.map((item) => artifactGroup(item, snapshot.artifact_groups).key));
    if (families.size !== 1) return null;
    return candidates.find((item) => source?.version && snapshot.artifact_groups?.[item.id]?.published_version === source.version) || candidates[0];
  }
  function groupFor(item: CatalogItem | null, source: CapturedScenario | null | undefined, fallback: string, name: string): BundleGroup {
    const lineage = item ? artifactGroup(item, snapshot.artifact_groups) : null;
    const key = lineage?.key || (source?.publisher ? JSON.stringify(["scenario", source.name, source.publisher])
      : source?.draft_id ? `draft:${source.draft_id}` : fallback);
    let group = groups.get(key);
    if (!group) {
      group = { key, name: item ? artifactTitle(item) : source?.display_name || source?.name || name, publisher: lineage?.publisher || source?.publisher || null, items: [], jobs: [], imports: [], owners: {} };
      groups.set(key, group);
    }
    if (item && !group.items.some((entry) => entry.id === item.id)) group.items.push(item);
    return group;
  }
  for (const job of snapshot.jobs.filter((entry) => entry.kind === "generation")) {
    const owner = scenarios.find((item) => item.path === job.scenario)
      || scenarios.find((item) => belongsToScenario(job, item, snapshot))
      || matchingSource(job.scenario_source);
    const name = job.scenario?.split(/[\\/]/).slice(-2, -1)[0] || "Unavailable scenario";
    const group = groupFor(owner, job.scenario_source, `source:${job.scenario || job.output_root}`, name === "source" ? "Unavailable scenario" : name);
    group.jobs.push(job);
    group.owners[job.id] = owner;
  }
  for (const bundle of snapshot.imported_bundles || []) {
    const owner = matchingSource(bundle.scenario_source, bundle.scenario_name);
    const source = bundle.scenario_source;
    const group = groupFor(owner, source, `imported:${bundle.scenario_name}`, bundle.scenario_name);
    group.imports.push(bundle);
    group.owners[bundle.id] = owner;
  }
  return [...groups.values()];
}
