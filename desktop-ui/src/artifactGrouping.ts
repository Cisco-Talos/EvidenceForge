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
