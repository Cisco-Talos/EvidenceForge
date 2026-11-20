import { SearchExcerpts } from "./SearchExcerpts";
import { artifactTitle, draftTitle } from "./artifactNaming";
import { artifactFamilies, artifactGroup, artifactGroupLabel, isDraftItem, type ArtifactFamily, type ArtifactGroups } from "./artifactGrouping";
import { DraftCount, FamilyToggle } from "./ScenarioLibrary";
import { Fragment, type DragEvent, type ReactNode } from "react";
import { Building2, Factory, Folder, GripVertical, PencilLine } from "lucide-react";
import { CatalogObjectMenu, projectAssignmentAction } from "./CatalogObjectMenu";
import { DraftObjectMenu } from "./DraftObjectMenu";
import type { CatalogItem, Conversation, Project } from "./api";
import { formatTime } from "./components";
import { groupRows, LibraryGroupHeading, libraryGroupKey, LibraryTable, sortRows, type LibraryColumn, type LibrarySort } from "./LibraryTable";

const typeLabels: Record<string, string> = { industry_pack: "Industry", organization_pack: "Organization" };

/** Industry and organization packs are told apart by shape: a factory or an office building. */
export function PackKindIcon({ kind, size = 16 }: { kind?: string | null; size?: number }) {
  return kind === "organization_pack" ? <Building2 size={size} aria-hidden="true" /> : <Factory size={size} aria-hidden="true" />;
}

const columns: LibraryColumn[] = [
  { key: "drag", label: "" }, { key: "expand", label: "" }, { key: "name", label: "Name", sort: "name" }, { key: "type", label: "Type" },
  { key: "version", label: "Version" }, { key: "project", label: "Project", sort: "project" }, { key: "updated", label: "Updated", sort: "updated" }, { key: "actions", label: "" },
];

export function PackLibrary({ items, drafts, projects, busy, artifactGroups, sort, onSort, expandedFamilies, onToggleFamily, collapsedGroups = [], onToggleGroup, dropTargetId, onProjectDragOver, onProjectDragLeave, onProjectDrop, onOpen, onProperties, onOpenDraft, onClone, onExport, onHide, onMove, onMoveDraft, onNewProject, onDelete, onDeleteDraft, onDragStart, onDraftDragStart, onDragEnd }: {
  items: CatalogItem[]; drafts: Conversation[]; projects: Project[]; busy: boolean;
  artifactGroups?: ArtifactGroups; sort: LibrarySort; onSort: (sort: LibrarySort) => void;
  /** Open family keys; a family row lists its other versions and drafts beneath it. */
  expandedFamilies: string[]; onToggleFamily: (key: string, open: boolean) => void;
  /** Collapsed project/publisher group keys (see `libraryGroupKey`). */
  collapsedGroups?: string[]; onToggleGroup?: (key: string, collapsed: boolean) => void;
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
  type Row = { id: string; name: string; updated: number; project: string; groupId: string; publisher: string; item: CatalogItem | null; draft: Conversation | null; family: ArtifactFamily | null };
  const publisherName = (item: CatalogItem) => item.publisher_display_name || item.publisher || "Unknown publisher";
  const rows = sortRows<Row>([
    ...artifactFamilies(items, artifactGroups).map((family): Row => ({ id: family.primary.id, name: artifactTitle(family.primary), updated: Math.max(family.primary.modified_at, ...family.others.map((other) => other.modified_at)), publisher: publisherName(family.primary), project: projectName(family.primary.project_id), groupId: groupId(family.primary.project_id), item: family.primary, draft: null, family })),
    ...drafts.map((draft): Row => ({ id: draft.id, name: draftTitle(draft), updated: draft.updated_at, publisher: "Unpublished drafts", project: projectName(draft.draft_project_id), groupId: groupId(draft.draft_project_id), item: null, draft, family: null })),
  ], sort);
  const renderDraft = (draft: Conversation) => <li className="pack-row library-row-grid pack-draft" key={draft.id} draggable onDragStart={(event) => onDraftDragStart(event, draft)} onDragEnd={onDragEnd}>
    <span className="pack-drag-handle col-drag" aria-hidden="true"><GripVertical size={14} /></span>
    <span className="col-expand" />
    <button className="pack-open col-name" onClick={() => onOpenDraft(draft)}><span className="scenario-symbol draft"><PencilLine size={16} /></span><span className="pack-row-copy"><strong>{draftTitle(draft)}</strong><small>{draft.active ? "Authoring in progress" : "Ready to author"}</small></span></button>
    <span className="col-type pack-cell pack-type"><PackKindIcon kind={draft.draft_kind} size={13} />{typeLabels[draft.draft_kind || ""] || "Pack"}</span>
    <span className="col-version"><DraftCount count={1} self /></span>
    <span className="col-project scenario-project"><Folder size={13} aria-hidden="true" /><span>{projectName(draft.draft_project_id)}</span></span>
    <time className="col-updated pack-cell" title={new Date(draft.updated_at * 1000).toLocaleString()}>{formatTime(draft.updated_at)}</time>
    <div className="col-actions"><DraftObjectMenu draft={draft} projects={projects} onOpen={() => onOpenDraft(draft)} onMove={(id) => onMoveDraft(draft, id)} onDelete={() => onDeleteDraft(draft)} /></div>
  </li>;
  const renderPack = (item: CatalogItem, toggle: ReactNode, child = false, drafts = 0) => <li key={item.id} data-artifact-identity={artifactGroupLabel(artifactGroup(item, artifactGroups))} className={`pack-row library-row-grid draggable-pack ${item.hidden ? "hidden-pack" : ""} ${child ? "family-member" : ""}`} draggable onDragStart={(event) => onDragStart(event, item)} onDragEnd={onDragEnd}>
    <span className="pack-drag-handle col-drag" aria-hidden="true" title={`Drag ${item.name} to a project`} draggable onDragStart={(event) => { event.stopPropagation(); onDragStart(event, item); }}><GripVertical size={14} /></span>
    <span className="col-expand">{toggle}</span>
    <button className="pack-open col-name" aria-label={`Open ${artifactTitle(item)} ${item.version}`} onClick={() => onOpen(item)}><span className={`scenario-symbol pack-kind-${item.kind === "organization_pack" ? "organization" : "industry"}`}><PackKindIcon kind={item.kind} /></span><span className="pack-row-copy">
      <strong title={`${artifactTitle(item)} · ${item.name}`}>{artifactTitle(item)}{item.hidden && <span className="draft-chip">Hidden</span>}{drafts > 0 && !isDraftItem(item, artifactGroups) && <DraftCount count={drafts} />}</strong>
      <small title={item.description}>{item.description || "No description yet"}</small><SearchExcerpts item={item} />
      <small className="pack-row-meta"><span title={`Publisher: ${item.publisher || "not recorded"}`}>By {item.publisher_display_name || item.publisher || "Unknown author"}</span><span>·</span><span title={item.pack_source === "bundled" ? "Included with EvidenceForge" : "Authored or imported in this workspace"}>{item.pack_source === "bundled" ? "Bundled" : "Workspace"}</span></small>
    </span></button>
    <span className="col-type pack-cell pack-type"><PackKindIcon kind={item.kind} size={13} />{typeLabels[item.kind] || "Pack"}</span>
    <span className="col-version">{isDraftItem(item, artifactGroups) ? <DraftCount count={child ? 1 : Math.max(1, drafts)} self /> : <span className="pack-version">{item.version}</span>}</span>
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
  const renderRows = (members: Row[]) => members.map((row) => {
    if (!row.item) return renderDraft(row.draft!);
    const family = row.family!;
    const open = expandedFamilies.includes(family.key);
    return <Fragment key={row.id}>
      {renderPack(row.item, family.others.length > 0 && <FamilyToggle name={row.name} count={family.others.length} open={open} onToggle={() => onToggleFamily(family.key, !open)} />, false, family.drafts)}
      {open && family.others.map((other) => renderPack(other, null, true))}
    </Fragment>;
  });
  return <LibraryTable label="Pack library" className="pack-table" columns={columns} sort={sort} onSort={onSort}>
    {groupRows(rows, sort).map((group) => {
      const key = libraryGroupKey("packs", sort, group.id);
      const collapsed = collapsedGroups.includes(key);
      const projectGroup = sort === "project";
      return <Fragment key={group.id || "all"}>
        {group.name && <LibraryGroupHeading name={group.name} count={group.rows.length} kind={projectGroup ? "project" : "publisher"}
          collapsed={collapsed} onToggle={onToggleGroup ? () => onToggleGroup(key, !collapsed) : undefined}
          dropTarget={projectGroup && dropTargetId === group.id}
          onDragOver={projectGroup ? (event) => onProjectDragOver(event, group.id === "ungrouped" ? null : group.id) : undefined} onDragLeave={projectGroup ? onProjectDragLeave : undefined}
          onDrop={projectGroup ? (event) => onProjectDrop(event, group.id === "ungrouped" ? null : group.id) : undefined} />}
        {!collapsed && renderRows(group.rows)}
      </Fragment>;
    })}
  </LibraryTable>;
}
