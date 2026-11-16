import { SearchExcerpts } from "./SearchExcerpts";
import { artifactTitle, draftTitle } from "./artifactNaming";
import { artifactGroup, artifactGroupLabel, type ArtifactGroups } from "./artifactGrouping";
import { Fragment, type DragEvent } from "react";
import { Folder, GripVertical, Layers3, PencilLine } from "lucide-react";
import { CatalogObjectMenu, projectAssignmentAction } from "./CatalogObjectMenu";
import { DraftObjectMenu } from "./DraftObjectMenu";
import type { CatalogItem, Conversation, Project } from "./api";
import { formatTime } from "./components";
import { groupRows, LibraryGroupHeading, LibraryTable, sortRows, type LibraryColumn, type LibrarySort } from "./LibraryTable";

const typeLabels: Record<string, string> = { industry_pack: "Industry", organization_pack: "Organization" };

const columns: LibraryColumn[] = [
  { key: "drag", label: "" }, { key: "name", label: "Name", sort: "name" }, { key: "type", label: "Type" },
  { key: "version", label: "Version" }, { key: "project", label: "Project", sort: "project" }, { key: "updated", label: "Updated", sort: "updated" }, { key: "actions", label: "" },
];

export function PackLibrary({ items, drafts, projects, busy, artifactGroups, sort, onSort, dropTargetId, onProjectDragOver, onProjectDragLeave, onProjectDrop, onOpen, onProperties, onOpenDraft, onClone, onExport, onHide, onMove, onMoveDraft, onNewProject, onDelete, onDeleteDraft, onDragStart, onDraftDragStart, onDragEnd }: {
  items: CatalogItem[]; drafts: Conversation[]; projects: Project[]; busy: boolean;
  artifactGroups?: ArtifactGroups; sort: LibrarySort; onSort: (sort: LibrarySort) => void;
  dropTargetId: string | null;
  onProjectDragOver: (event: DragEvent<HTMLElement>, projectId: string | null) => void;
  onProjectDragLeave: (event: DragEvent<HTMLElement>) => void;
  onProjectDrop: (event: DragEvent<HTMLElement>, projectId: string | null) => void;
  onOpen: (item: CatalogItem) => void; onProperties?: (item: CatalogItem) => void; onOpenDraft: (draft: Conversation) => void; onClone: (item: CatalogItem) => void; onExport: (item: CatalogItem) => void;
  onHide: (item: CatalogItem) => void; onMove: (item: CatalogItem, projectId: string | null) => void;
  onMoveDraft: (draft: Conversation, projectId: string | null) => void;
  onDelete: (item: CatalogItem) => void; onNewProject: (item: CatalogItem) => void; onDeleteDraft: (draft: Conversation) => void;
  onDragStart: (event: DragEvent<HTMLElement>, item: CatalogItem) => void;
  onDraftDragStart: (event: DragEvent<HTMLElement>, draft: Conversation) => void; onDragEnd: () => void;
}) {
  const projectName = (id: string | null) => projects.find((project) => project.id === id)?.name || "Ungrouped";
  const groupId = (id: string | null) => projects.some((project) => project.id === id) ? id! : "ungrouped";
  const rows = sortRows([
    ...items.map((item) => ({ id: item.id, name: artifactTitle(item), updated: item.modified_at, project: projectName(item.project_id), groupId: groupId(item.project_id), item, draft: null })),
    ...drafts.map((draft) => ({ id: draft.id, name: draftTitle(draft), updated: draft.updated_at, project: projectName(draft.draft_project_id), groupId: groupId(draft.draft_project_id), item: null, draft })),
  ], sort);
  const identity = (row: typeof rows[number]) => row.item ? artifactGroup(row.item, artifactGroups).key : row.id;
  const renderDraft = (draft: Conversation) => <li className="pack-row library-row-grid pack-draft" key={draft.id} draggable onDragStart={(event) => onDraftDragStart(event, draft)} onDragEnd={onDragEnd}>
    <span className="pack-drag-handle col-drag" aria-hidden="true"><GripVertical size={14} /></span>
    <button className="pack-open col-name" onClick={() => onOpenDraft(draft)}><span className="scenario-symbol draft"><PencilLine size={16} /></span><span className="pack-row-copy"><strong>{draftTitle(draft)}</strong><small>{draft.active ? "Authoring in progress" : "Ready to author"}</small></span></button>
    <span className="col-type pack-cell">{typeLabels[draft.draft_kind || ""] || "Pack"}</span>
    <span className="col-version"><span className="draft-chip">Draft</span></span>
    <span className="col-project scenario-project"><Folder size={13} aria-hidden="true" /><span>{projectName(draft.draft_project_id)}</span></span>
    <time className="col-updated pack-cell" title={new Date(draft.updated_at * 1000).toLocaleString()}>{formatTime(draft.updated_at)}</time>
    <div className="col-actions"><DraftObjectMenu draft={draft} projects={projects} onOpen={() => onOpenDraft(draft)} onMove={(id) => onMoveDraft(draft, id)} onDelete={() => onDeleteDraft(draft)} /></div>
  </li>;
  const renderPack = (item: CatalogItem) => <li key={item.id} data-artifact-identity={artifactGroupLabel(artifactGroup(item, artifactGroups))} className={`pack-row library-row-grid draggable-pack ${item.hidden ? "hidden-pack" : ""}`} draggable onDragStart={(event) => onDragStart(event, item)} onDragEnd={onDragEnd}>
    <span className="pack-drag-handle col-drag" aria-hidden="true" title={`Drag ${item.name} to a project`} draggable onDragStart={(event) => { event.stopPropagation(); onDragStart(event, item); }}><GripVertical size={14} /></span>
    <button className="pack-open col-name" aria-label={`Open ${artifactTitle(item)} ${item.version}`} onClick={() => onOpen(item)}><span className="scenario-symbol"><Layers3 size={16} /></span><span className="pack-row-copy">
      <strong title={`${artifactTitle(item)} · ${item.name}`}>{artifactTitle(item)}{item.hidden && <span className="draft-chip">Hidden</span>}</strong>
      <small title={item.description}>{item.description || "No description yet"}</small><SearchExcerpts item={item} />
      <small className="pack-row-meta"><span title={`Publisher: ${item.publisher || "not recorded"}`}>By {item.publisher_display_name || item.publisher || "Unknown author"}</span><span>·</span><span title={item.pack_source === "bundled" ? "Included with EvidenceForge" : "Authored or imported in this workspace"}>{item.pack_source === "bundled" ? "Bundled" : "Workspace"}</span></small>
    </span></button>
    <span className="col-type pack-cell">{typeLabels[item.kind] || "Pack"}</span>
    <span className="col-version"><span className="pack-version">{item.version || "Draft"}</span></span>
    <span className="col-project scenario-project"><Folder size={13} aria-hidden="true" /><span>{projectName(item.project_id)}</span></span>
    <time className="col-updated pack-cell" title={new Date(item.modified_at * 1000).toLocaleString()}>{formatTime(item.modified_at)}</time>
    <div className="col-actions"><CatalogObjectMenu item={item} fallbackActions={[
      { id: "open", label: "Open", group: "inspect", run: () => onOpen(item) },
      { id: "properties", label: "Properties…", group: "locate", run: () => onProperties?.(item) },
      { id: "clone", label: "Duplicate…", group: "manage", run: () => onClone(item) },
      { id: "export", label: "Export release…", group: "manage", disabled: !item.version, reason: "Publish a release before exporting", run: () => onExport(item) },
      projectAssignmentAction(projects, (id) => onMove(item, id), () => onNewProject(item)),
      { id: "hide", label: item.hidden ? "Show in library" : "Hide from library", group: "organize", run: () => onHide(item) },
      ...(item.pack_source === "workspace" ? [{ id: "delete", label: "Delete version…", group: "remove" as const, disabled: busy, reason: "An operation is in progress", run: () => onDelete(item) }] : []),
    ]} /></div>
  </li>;
  const newestFirst = (a: typeof rows[number], b: typeof rows[number]) => (b.item?.version || "").localeCompare(a.item?.version || "", undefined, { numeric: true }) || a.id.localeCompare(b.id);
  /** Keep each pack's versions together, ordered newest first, and order the families by the library sort. */
  const renderRows = (members: typeof rows) => {
    const families = [...new Set(members.map(identity))].map((key) => members.filter((row) => identity(row) === key).sort(newestFirst));
    families.sort((a, b) => {
      if (sort === "updated") return Math.max(...b.map((row) => row.updated)) - Math.max(...a.map((row) => row.updated));
      const [first, second] = [a[0], b[0]];
      return first.name.localeCompare(second.name, undefined, { sensitivity: "base" }) || (first.item?.name || "").localeCompare(second.item?.name || "")
        || (first.item ? artifactGroup(first.item, artifactGroups).publisher || "" : "").localeCompare(second.item ? artifactGroup(second.item, artifactGroups).publisher || "" : "")
        || newestFirst(first, second);
    });
    return families.map((family) => {
      const first = family[0].item;
      return <Fragment key={identity(family[0])}>
        {first && family.length > 1 && <li className="artifact-identity-heading">{artifactGroupLabel(artifactGroup(first, artifactGroups))} · drafts & releases</li>}
        {family.map((row) => row.item ? renderPack(row.item) : renderDraft(row.draft!))}
      </Fragment>;
    });
  };
  return <LibraryTable label="Pack library" className="pack-table" columns={columns} sort={sort} onSort={onSort}>
    {groupRows(rows, sort).map((group) => <Fragment key={group.id || "all"}>
      {group.name && <LibraryGroupHeading name={group.name} count={group.rows.length} dropTarget={dropTargetId === group.id}
        onDragOver={(event) => onProjectDragOver(event, group.id === "ungrouped" ? null : group.id)} onDragLeave={onProjectDragLeave}
        onDrop={(event) => onProjectDrop(event, group.id === "ungrouped" ? null : group.id)} />}
      {renderRows(group.rows)}
    </Fragment>)}
  </LibraryTable>;
}
