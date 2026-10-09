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
