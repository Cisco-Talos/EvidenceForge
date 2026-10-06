import { Filter, RotateCcw, X } from "lucide-react";
import { Popover } from "radix-ui";
import type { CatalogItem } from "./api";

export type PackFilterValues = { publisher: string; version: string; source: string };
export const emptyPackFilters: PackFilterValues = { publisher: "", version: "", source: "" };

export function PackFilters({ items, kind, values, showHidden, onKind, onChange, onHidden, onReset }: {
  items: CatalogItem[]; kind: "packs" | "industry_pack" | "organization_pack"; values: PackFilterValues; showHidden: boolean;
  onKind: (kind: "packs" | "industry_pack" | "organization_pack") => void;
  onChange: (values: PackFilterValues) => void; onHidden: (value: boolean) => void; onReset: () => void;
}) {
  const authors = [...new Map(items.filter((item) => item.publisher).map((item) => [item.publisher!, item.publisher_display_name || item.publisher!])).entries()].sort((a, b) => a[1].localeCompare(b[1]));
  const versions = [...new Set(items.map((item) => item.version).filter(Boolean))].sort();
  const count = Number(kind !== "packs") + Number(showHidden) + Object.values(values).filter(Boolean).length;
  return <Popover.Root><Popover.Trigger className={`folder-filter-trigger pack-filters-trigger ${count ? "active" : ""}`} aria-label="Filter packs" title={count ? `${count} active pack filters` : "Filter packs"}><Filter size={17} />{count > 0 && <span className="filter-count">{count}</span>}</Popover.Trigger><Popover.Portal><Popover.Content className="pack-filters-popover" sideOffset={8} align="end" collisionPadding={12}>
    <div className="pack-filter-heading"><strong>Filter packs</strong><Popover.Close className="icon-button" aria-label="Close pack filters"><X size={15} /></Popover.Close></div>
    <label className="modal-field">Type<select aria-label="Pack type" value={kind} onChange={(event) => onKind(event.target.value as typeof kind)}><option value="packs">All types</option><option value="industry_pack">Industry</option><option value="organization_pack">Organization</option></select></label>
    <label className="modal-field">Author<select aria-label="Pack author" value={values.publisher} onChange={(event) => onChange({ ...values, publisher: event.target.value })}><option value="">All authors</option>{authors.map(([id, display]) => <option key={id} value={id}>{display} ({id})</option>)}</select></label>
    <div className="pack-form-pair"><label className="modal-field">Version<select aria-label="Pack version filter" value={values.version} onChange={(event) => onChange({ ...values, version: event.target.value })}><option value="">All versions</option>{versions.map((version) => <option key={version}>{version}</option>)}</select></label>
      <label className="modal-field">Location<select aria-label="Pack location" value={values.source} onChange={(event) => onChange({ ...values, source: event.target.value })}><option value="">All locations</option><option value="workspace">Workspace</option><option value="bundled">Bundled</option></select></label></div>
    <label className="pack-filter-check"><input type="checkbox" className="visible-check" checked={showHidden} onChange={(event) => onHidden(event.target.checked)} />Include hidden packs</label>
    <button type="button" className="button-quiet" disabled={!count} onClick={onReset}><RotateCcw size={14} />Reset filters</button>
  </Popover.Content></Popover.Portal></Popover.Root>;
}
