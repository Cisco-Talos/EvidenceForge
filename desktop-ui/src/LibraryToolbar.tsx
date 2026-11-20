import type { ReactNode } from "react";
import { Bookmark, Check, ChevronDown, Filter, RotateCcw, Search, X } from "lucide-react";
import { DropdownMenu, Popover } from "radix-ui";
import { sortLabels, type LibrarySort } from "./LibraryTable";

export interface FilterFacet {
  id: string; label: string; value: string;
  /** Select facets list options with an "all" choice; text facets match free text. */
  allLabel?: string; options?: { value: string; label: string }[]; placeholder?: string;
  onChange: (value: string) => void;
}
export interface FilterToggle { id: string; label: string; checked: boolean; onChange: (checked: boolean) => void }

/** Every library filter lives in one popover; the trigger shows how many are active. */
export function LibraryFilters({ label, facets = [], toggles = [], onReset }: {
  label: string; facets?: FilterFacet[]; toggles?: FilterToggle[]; onReset: () => void;
}) {
  const count = facets.filter((facet) => facet.value).length + toggles.filter((toggle) => toggle.checked).length;
  return <Popover.Root>
    <Popover.Trigger className={`toolbar-button ${count ? "active" : ""}`} aria-label={label} title={count ? `${count} active ${count === 1 ? "filter" : "filters"}` : label}>
      <Filter size={15} aria-hidden="true" />Filter{count > 0 && <span className="filter-count">{count}</span>}
    </Popover.Trigger>
    <Popover.Portal><Popover.Content className="pack-filters-popover" sideOffset={8} align="start" collisionPadding={12}>
      <div className="pack-filter-heading"><strong>{label}</strong><Popover.Close className="icon-button" aria-label={`Close ${label.toLowerCase()}`}><X size={15} /></Popover.Close></div>
      {facets.map((facet) => <label key={facet.id} className="modal-field">{facet.label}{facet.options
        ? <select aria-label={facet.label} value={facet.value} onChange={(event) => facet.onChange(event.target.value)}><option value="">{facet.allLabel || "All"}</option>{facet.options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select>
        : <input aria-label={facet.label} maxLength={200} placeholder={facet.placeholder} value={facet.value} onChange={(event) => facet.onChange(event.target.value)} />}</label>)}
      {!facets.length && !toggles.length && <p className="filter-empty">Hidden items and previous versions appear here when this library has them.</p>}
      {toggles.map((toggle) => <label key={toggle.id} className="pack-filter-check"><input type="checkbox" className="visible-check" checked={toggle.checked} onChange={(event) => toggle.onChange(event.target.checked)} />{toggle.label}</label>)}
      <button type="button" className="button-quiet" disabled={!count} onClick={onReset}><RotateCcw size={14} />Reset filters</button>
    </Popover.Content></Popover.Portal>
  </Popover.Root>;
}

/**
 * Ordering/layout and saved views. Saved views return to a search, its filters and project.
 * Libraries pass `LibrarySort` values; other pages (Activity) pass their own layouts with labels.
 */
export function ViewsMenu<T extends string = LibrarySort>({ sort, onSort, views, onApply, onManage, options = Object.keys(sortLabels) as T[], labels = {}, heading = "Sort" }: {
  sort: T; onSort: (sort: T) => void;
  /** Saved views; omit for libraries without them. */
  views?: { name: string; detail: string }[]; onApply?: (name: string) => void; onManage?: () => void;
  options?: T[]; labels?: Partial<Record<T, string>>; heading?: string;
}) {
  return <DropdownMenu.Root>
    <DropdownMenu.Trigger className="toolbar-button" aria-label="Views"><Bookmark size={15} aria-hidden="true" />Views<ChevronDown size={13} aria-hidden="true" /></DropdownMenu.Trigger>
    <DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu views-menu" sideOffset={6} align="start">
      <DropdownMenu.Label className="menu-label">{heading}</DropdownMenu.Label>
      <DropdownMenu.RadioGroup value={sort} onValueChange={(value) => onSort(value as T)}>
        {options.map((value) => <DropdownMenu.RadioItem key={value} value={value} className="object-action-item menu-radio">
          <DropdownMenu.ItemIndicator className="menu-indicator"><Check size={13} /></DropdownMenu.ItemIndicator>{labels[value] || sortLabels[value as unknown as LibrarySort] || value}
        </DropdownMenu.RadioItem>)}
      </DropdownMenu.RadioGroup>
      {views && <>
      <DropdownMenu.Separator className="menu-separator" />
      <DropdownMenu.Label className="menu-label">Saved views</DropdownMenu.Label>
      {views.length ? views.map((view) => <DropdownMenu.Item key={view.name} className="object-action-item" aria-label={`Apply saved view ${view.name}`} onSelect={() => onApply?.(view.name)}><span className="object-action-copy"><span>{view.name}</span><small>{view.detail}</small></span></DropdownMenu.Item>)
        : <div className="menu-empty">No saved views yet</div>}
      <DropdownMenu.Separator className="menu-separator" />
      <DropdownMenu.Item className="object-action-item" onSelect={() => onManage?.()}>Save or manage views…</DropdownMenu.Item>
      </>}
    </DropdownMenu.Content></DropdownMenu.Portal>
  </DropdownMenu.Root>;
}

/** The shared library toolbar: search, filters, views and a result count. */
export function LibraryToolbar({ search, onSearch, searchLabel, placeholder, filters, views, count, noun, children }: {
  search: string; onSearch: (value: string) => void; searchLabel: string; placeholder: string;
  filters?: ReactNode; views?: ReactNode; count: number; noun: [string, string]; children?: ReactNode;
}) {
  return <div className="library-toolbar">
    <div className="search-box"><Search size={15} aria-hidden="true" /><input placeholder={placeholder} value={search} onChange={(event) => onSearch(event.target.value)} aria-label={searchLabel} />{search && <button type="button" className="search-clear" aria-label="Clear search" onClick={() => onSearch("")}><X size={13} /></button>}</div>
    {filters}{views}
    <span className="result-count">{count} {count === 1 ? noun[0] : noun[1]}</span>
    {children}
  </div>;
}
