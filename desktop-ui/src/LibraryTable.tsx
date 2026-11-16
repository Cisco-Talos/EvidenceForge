import type { DragEvent, ReactNode } from "react";
import { ArrowDown, Folder } from "lucide-react";

/** Library ordering. `project` groups rows under static project headings. */
export type LibrarySort = "name" | "updated" | "project";

export const sortLabels: Record<LibrarySort, string> = { name: "Name A–Z", updated: "Recently updated", project: "Group by project" };

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

/** A static group heading inside a grouped library; also a drop target for moving rows. */
export function LibraryGroupHeading({ name, count, dropTarget = false, onDragOver, onDragLeave, onDrop }: {
  name: string; count: number; dropTarget?: boolean;
  onDragOver?: (event: DragEvent<HTMLElement>) => void; onDragLeave?: (event: DragEvent<HTMLElement>) => void; onDrop?: (event: DragEvent<HTMLElement>) => void;
}) {
  return <li className={`library-group-heading ${dropTarget ? "drop-target" : ""}`} onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}>
    <Folder size={14} aria-hidden="true" /><strong>{name}</strong><span>{count}</span>
  </li>;
}

/** Order rows by the library sort; `project` keeps name order within each project. */
export function sortRows<T extends { name: string; id: string; updated: number; project: string }>(rows: T[], sort: LibrarySort): T[] {
  return [...rows].sort((a, b) => (sort === "updated" ? b.updated - a.updated : sort === "project" ? a.project.localeCompare(b.project) : 0)
    || a.name.localeCompare(b.name, undefined, { sensitivity: "base" }) || a.id.localeCompare(b.id));
}

/** Split sorted rows into project groups, preserving order; returns one unnamed group when not grouping. */
export function groupRows<T extends { groupId: string; project: string }>(rows: T[], sort: LibrarySort): { id: string; name: string; rows: T[] }[] {
  if (sort !== "project") return [{ id: "", name: "", rows }];
  const groups = new Map<string, { id: string; name: string; rows: T[] }>();
  for (const row of rows) {
    const group = groups.get(row.groupId) || { id: row.groupId, name: row.project, rows: [] };
    group.rows.push(row);
    groups.set(row.groupId, group);
  }
  return [...groups.values()];
}
