import type { CatalogItem, DependencyRow, SelectedPack } from "./api";

function identity(pack: Pick<SelectedPack, "publisher" | "type" | "name" | "version">): string {
  return `${pack.publisher}:${pack.type}:${pack.name}@${pack.version}`;
}

export function selectedPackItem(pack: SelectedPack, items: CatalogItem[]): CatalogItem | undefined {
  // Portable composition metadata deliberately omits physical paths. Path packs
  // need the resolved dependency row below rather than an identity-only match.
  if (pack.source === "path") return undefined;
  const matches = items.filter((item) =>
    item.kind === `${pack.type}_pack` && item.publisher === pack.publisher &&
    item.name === pack.name && item.version === pack.version &&
    item.pack_source === (pack.source === "package" ? "bundled" : "workspace"));
  return matches.length === 1 ? matches[0] : undefined;
}

export function dependencyPackItem(row: DependencyRow, selected: SelectedPack[], items: CatalogItem[]): CatalogItem | undefined {
  if (row.kind !== "pack" || row.status === "missing") return undefined;
  if (row.source) {
    const source = row.source.replace(/\\/g, "/");
    const matches = items.filter((item) => item.kind !== "scenario" &&
      `${item.publisher}:${item.kind === "industry_pack" ? "industry" : "organization"}:${item.name}@${item.version}` === row.key &&
      item.path.replace(/\\/g, "/") === source);
    return matches.length === 1 ? matches[0] : undefined;
  }
  const resolved = selected.filter((pack) => identity(pack) === row.key && (!row.digest || pack.digest === row.digest));
  const matches = resolved.map((pack) => selectedPackItem(pack, items)).filter((item) => item !== undefined);
  return matches.length === 1 ? matches[0] : undefined;
}
