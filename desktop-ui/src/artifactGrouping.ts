import type { CatalogItem, StudioSnapshot } from "./api";

export type ArtifactGroups = NonNullable<StudioSnapshot["artifact_groups"]>;

export function artifactGroup(item: CatalogItem, groups?: ArtifactGroups) {
  return groups?.[item.id] || {
    key: JSON.stringify([item.kind, item.name, item.publisher || `unassigned:${item.id}`]),
    name: item.name,
    publisher: item.publisher || null,
  };
}

export function artifactGroupLabel(group: ReturnType<typeof artifactGroup>) {
  return `${group.publisher || "anonymous"}/${group.name}`;
}

/** Keep active drafts and legacy files, and select the newest release in each family. */
export function latestPublishedItems(items: CatalogItem[], groups?: ArtifactGroups): CatalogItem[] {
  const latest = new Map<string, CatalogItem>();
  for (const item of items) {
    const version = groups?.[item.id]?.published_version;
    if (!version) continue;
    const key = artifactGroup(item, groups).key;
    const previous = latest.get(key);
    if (!previous || version.localeCompare(groups![previous.id].published_version!, undefined, { numeric: true }) > 0) latest.set(key, item);
  }
  return items.filter((item) => !groups?.[item.id]?.published_version || latest.get(artifactGroup(item, groups).key)?.id === item.id);
}

/** One library row per artifact family: its newest version, and the other versions and drafts. */
export interface ArtifactFamily {
  key: string; primary: CatalogItem; others: CatalogItem[];
  /** Unpublished drafts in the family, including the primary when it is itself a draft. */
  drafts: number;
  /** The family has no release yet, so its headline row is a draft. */
  primaryIsDraft: boolean;
}

/** True for unpublished drafts: items with neither a published nor an authored release version. */
export function isDraftItem(item: CatalogItem, groups?: ArtifactGroups): boolean {
  return !releaseVersion(item, groups);
}

/** A comparable release version: the published version, else a non-draft authored version. */
function releaseVersion(item: CatalogItem, groups?: ArtifactGroups): string {
  const published = groups?.[item.id]?.published_version;
  if (published) return published;
  return item.version && item.version !== "Draft" ? item.version : "";
}

const newestVersion = (groups?: ArtifactGroups) => (a: CatalogItem, b: CatalogItem) =>
  releaseVersion(b, groups).localeCompare(releaseVersion(a, groups), undefined, { numeric: true }) || b.modified_at - a.modified_at || a.id.localeCompare(b.id);

/**
 * Group items by family. The primary is the newest published release, else the newest versioned
 * legacy file (such as a bundled pack), else the most recently edited draft. Others list drafts
 * first, then the remaining versions newest first.
 */
export function artifactFamilies(items: CatalogItem[], groups?: ArtifactGroups): ArtifactFamily[] {
  const families = new Map<string, CatalogItem[]>();
  for (const item of items) {
    const key = artifactGroup(item, groups).key;
    families.set(key, [...(families.get(key) || []), item]);
  }
  return [...families.entries()].map(([key, members]) => {
    // Published releases outrank legacy versioned files, which outrank drafts.
    const published = members.filter((item) => groups?.[item.id]?.published_version).sort(newestVersion(groups));
    const legacy = members.filter((item) => !groups?.[item.id]?.published_version && releaseVersion(item, groups)).sort(newestVersion(groups));
    const releases = [...published, ...legacy];
    const drafts = members.filter((item) => !releaseVersion(item, groups)).sort((a, b) => b.modified_at - a.modified_at || a.id.localeCompare(b.id));
    const primary = releases[0] || drafts[0];
    const others = [...drafts, ...releases].filter((item) => item.id !== primary.id);
    return { key, primary, others, drafts: drafts.length, primaryIsDraft: !releaseVersion(primary, groups) };
  });
}
