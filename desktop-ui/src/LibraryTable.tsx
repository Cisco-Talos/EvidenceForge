import type { DragEvent, ReactNode } from "react";
import { ArrowDown, ChevronRight, Folder, UserRound } from "lucide-react";

/**
 * Library ordering. `project` and `publisher` group rows under collapsible headings; versions of
 * one artifact always stay folded into their family row inside whichever group holds them.
 */
export type LibrarySort = "name" | "updated" | "project" | "publisher";

export const sortLabels: Record<LibrarySort, string> = { name: "Name A–Z", updated: "Recently updated", project: "Group by project", publisher: "Group by publisher" };

/** Scenario libraries offer project grouping; pack libraries can also group by publisher. */
export const scenarioSortOptions: LibrarySort[] = ["name", "updated", "project"];
export const packSortOptions: LibrarySort[] = ["name", "updated", "project", "publisher"];

export interface LibraryColumn {
  /** Cell class suffix: header and row cells share `col-${key}` so responsive rules hide both. */
  key: string;
  label: string;
  /** Clicking the heading applies this ordering. */
  sort?: LibrarySort;
}

/**
 * The one library layout: a labelled list of rows under sortable column headings. Column widths
 * live in CSS on the table's `className` so container queries can drop columns on narrow windows.
 */
export function LibraryTable({ label, className, columns, sort, onSort, children }: {
  label: string; className: string; columns: LibraryColumn[]; sort?: LibrarySort; onSort?: (sort: LibrarySort) => void; children: ReactNode;
}) {
  return <div className={`library-table ${className}`}>
    <div className="library-table-head library-row-grid" aria-hidden="true">
      {columns.map((column) => <div key={column.key} className={`library-heading col-${column.key}`}>
        {column.sort && onSort ? <button type="button" tabIndex={-1} className={sort === column.sort ? "active" : ""} onClick={() => onSort(column.sort!)}>{column.label}{sort === column.sort && <ArrowDown size={12} />}</button> : column.label}
      </div>)}
    </div>
    <ul className="library-table-body" aria-label={label}>{children}</ul>
  </div>;
}

/**
 * A collapsible group heading inside a grouped library. Project headings are also drop targets for
 * moving rows; groups start expanded so items show immediately.
 */
export function LibraryGroupHeading({ name, count, collapsed = false, onToggle, kind = "project", dropTarget = false, onDragOver, onDragLeave, onDrop }: {
  name: string; count: number; collapsed?: boolean; onToggle?: () => void; kind?: "project" | "publisher"; dropTarget?: boolean;
  onDragOver?: (event: DragEvent<HTMLElement>) => void; onDragLeave?: (event: DragEvent<HTMLElement>) => void; onDrop?: (event: DragEvent<HTMLElement>) => void;
}) {
  const icon = kind === "publisher" ? <UserRound size={14} aria-hidden="true" /> : <Folder size={14} aria-hidden="true" />;
  return <li className={`library-group-heading ${dropTarget ? "drop-target" : ""}`} onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}>
    {onToggle
      ? <button type="button" className="library-group-toggle" aria-expanded={!collapsed} aria-label={`${collapsed ? "Expand" : "Collapse"} ${name}`} onClick={onToggle}>
        <ChevronRight size={14} aria-hidden="true" className={collapsed ? "" : "open"} />{icon}<strong>{name}</strong><span>{count}</span>
      </button>
      : <>{icon}<strong>{name}</strong><span>{count}</span></>}
  </li>;
}

/** Stable key for a group's collapsed state; separate per library and grouping mode. */
export function libraryGroupKey(library: string, sort: LibrarySort, groupId: string): string {
  return `${library}:${sort}:${groupId}`;
}

interface GroupableRow { name: string; id: string; updated: number; project: string; groupId: string; publisher?: string }

const UNKNOWN_PUBLISHER = "Unknown publisher";
const compareNames = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base" });

/** Order rows by the library sort; grouped sorts keep name order within each group. */
export function sortRows<T extends Omit<GroupableRow, "groupId"> & { groupId?: string }>(rows: T[], sort: LibrarySort): T[] {
  return [...rows].sort((a, b) => (sort === "updated" ? b.updated - a.updated
    : sort === "project" ? compareNames(a.project, b.project)
    : sort === "publisher" ? compareNames(a.publisher || UNKNOWN_PUBLISHER, b.publisher || UNKNOWN_PUBLISHER) : 0)
    || compareNames(a.name, b.name) || a.id.localeCompare(b.id));
}

/** Split sorted rows into project or publisher groups, preserving order; one unnamed group otherwise. */
export function groupRows<T extends GroupableRow>(rows: T[], sort: LibrarySort): { id: string; name: string; rows: T[] }[] {
  if (sort !== "project" && sort !== "publisher") return [{ id: "", name: "", rows }];
  const groups = new Map<string, { id: string; name: string; rows: T[] }>();
  for (const row of rows) {
    const id = sort === "publisher" ? `publisher:${row.publisher || UNKNOWN_PUBLISHER}` : row.groupId;
    const name = sort === "publisher" ? row.publisher || UNKNOWN_PUBLISHER : row.project;
    const group = groups.get(id) || { id, name, rows: [] };
    group.rows.push(row);
    groups.set(id, group);
  }
  return [...groups.values()];
}
