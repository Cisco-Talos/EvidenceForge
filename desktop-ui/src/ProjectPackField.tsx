import type { CatalogItem } from "./api";
import type { components } from "./generated/studio";
import { artifactTitle } from "./artifactNaming";

export type ProjectDefaultPack = components["schemas"]["ProjectDefaultPack"];

/** A stable select value for one exact released pack; "" means no default. */
export function projectPackKey(pack: ProjectDefaultPack | null | undefined): string {
  return pack ? [pack.kind, pack.publisher, pack.name, pack.version].join("|") : "";
}

export function parseProjectPackKey(key: string): ProjectDefaultPack | null {
  const [kind, publisher, name, version] = key.split("|");
  return key && (kind === "industry" || kind === "organization") && publisher && name && version
    ? { kind, publisher, name, version } : null;
}

const packKinds = [["organization", "organization_pack", "Organization packs"], ["industry", "industry_pack", "Industry packs"]] as const;

/**
 * The project's default pack for new scenario authoring in Studio. Only released packs qualify,
 * so the reference stays exact; a scenario file still declares its own packs.
 */
export function ProjectPackField({ value, items, onChange }: { value: string; items: CatalogItem[]; onChange: (value: string) => void }) {
  const released = (kind: string) => items
    .filter((item) => item.kind === kind && item.version && item.publisher)
    .sort((a, b) => artifactTitle(a).localeCompare(artifactTitle(b)) || b.version.localeCompare(a.version, undefined, { numeric: true }));
  // Keep a saved default visible even if that release is no longer in the library.
  const known = new Set(packKinds.flatMap(([kind, itemKind]) => released(itemKind).map((item) => projectPackKey({ kind, publisher: item.publisher, name: item.name, version: item.version }))));
  const missing = value && !known.has(value) ? parseProjectPackKey(value) : null;
  return <label className="modal-field">Default pack for new scenarios
    <select aria-label="Default pack for new scenarios" value={value} onChange={(event) => onChange(event.target.value)}>
      <option value="">None</option>
      {packKinds.map(([kind, itemKind, label]) => {
        const options = released(itemKind);
        return options.length ? <optgroup key={kind} label={label}>{options.map((item) => {
          const key = projectPackKey({ kind, publisher: item.publisher, name: item.name, version: item.version });
          return <option key={key} value={key}>{`${artifactTitle(item)} ${item.version} · ${item.publisher_display_name || item.publisher}`}</option>;
        })}</optgroup> : null;
      })}
      {missing && <option value={value}>{`${missing.publisher}/${missing.name} ${missing.version} (not in library)`}</option>}
    </select>
    <small>Codex starts new scenarios in this project with it. Scenario files keep their own pack choices.</small>
  </label>;
}
