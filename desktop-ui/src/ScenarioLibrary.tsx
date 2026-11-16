import { belongsToScenario } from "./scenarioSources";
import { artifactTitle, draftTitle } from "./artifactNaming";
import { artifactFamilies, type ArtifactFamily } from "./artifactGrouping";
import { Fragment, type DragEvent, useEffect, useState } from "react";
import { ChevronRight, FileCode2, Folder, GripVertical, PencilLine } from "lucide-react";
import type { CatalogItem, Conversation, Project, StudioApi, StudioSnapshot } from "./api";
import { formatBundleSize, formatTime } from "./components";
import { CatalogObjectMenu, projectAssignmentAction } from "./CatalogObjectMenu";
import { DraftObjectMenu } from "./DraftObjectMenu";
import { ScenarioStatusPill, scenarioStates } from "./ScenarioStates";
import { SearchExcerpts } from "./SearchExcerpts";
import { generationIsCurrent } from "./ScenarioStates";
import { currentPrediction } from "./ResourceForecastPanel";
import { StatusPill } from "./StatusPill";
import { groupRows, LibraryGroupHeading, LibraryTable, sortRows, type LibraryColumn, type LibrarySort } from "./LibraryTable";

export type ScenarioSort = LibrarySort;

const columns: LibraryColumn[] = [
  { key: "drag", label: "" }, { key: "expand", label: "" }, { key: "name", label: "Name", sort: "name" }, { key: "project", label: "Project", sort: "project" },
  { key: "status", label: "Status" }, { key: "size", label: "Size" }, { key: "updated", label: "Updated", sort: "updated" }, { key: "actions", label: "" },
];

export function ScenarioLibrary({ items, drafts, snapshot, api, sort, onSort, expandedFamilies, onToggleFamily, onOpen, onProperties, onOpenDraft, onClone,
  onExport, onHide, onDelete, onMove, onMoveDraft, onNewProject, onRenameDraft,
  onDeleteDraft, onDragStart, onDraftDragStart, onDragEnd, dropTargetId, onProjectDragOver, onProjectDragLeave, onProjectDrop }: {
  dropTargetId: string | null;
  /** Open family keys; a family row lists its other versions and drafts beneath it. */
  expandedFamilies: string[]; onToggleFamily: (key: string, open: boolean) => void;
  onProjectDragOver: (event: DragEvent<HTMLElement>, projectId: string | null) => void;
  onProjectDragLeave: (event: DragEvent<HTMLElement>) => void;
  onProjectDrop: (event: DragEvent<HTMLElement>, projectId: string | null) => void;
  items: CatalogItem[]; drafts: Conversation[]; snapshot: StudioSnapshot; api: StudioApi; sort: ScenarioSort; onSort: (sort: ScenarioSort) => void;
  onOpen: (item: CatalogItem) => void; onProperties?: (item: CatalogItem) => void; onOpenDraft: (draft: Conversation) => void;
  onClone: (item: CatalogItem) => void; onExport: (item: CatalogItem) => void;
  onUnavailableExport: () => void; onHide: (item: CatalogItem) => void; onDelete: (item: CatalogItem) => void;
  onMove: (item: CatalogItem, projectId: string | null) => void;
  onMoveDraft: (draft: Conversation, projectId: string | null) => void;
  onNewProject: (item: CatalogItem) => void; onRenameDraft: (draft: Conversation) => void;
  onDeleteDraft: (draft: Conversation) => void;
  onDragStart: (event: DragEvent<HTMLElement>, item: CatalogItem) => void;
  onDraftDragStart: (event: DragEvent<HTMLElement>, draft: Conversation) => void;
  onDragEnd: () => void;
}) {
  const [sizes, setSizes] = useState<Record<string, number | null>>({});
  const completedKey = snapshot.jobs.filter((job) => job.kind === "generation" && job.status === "completed").map((job) => job.id).sort().join(":");
  useEffect(() => {
    let cancelled = false;
    setSizes({});
    if (completedKey) void api.bundleSizes().then((result) => { if (!cancelled) setSizes(result); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [api, snapshot.settings.workspace, completedKey]);
  const projectName = (id: string | null) => snapshot.projects.find((project: Project) => project.id === id)?.name || "Ungrouped";
  type Row = { id: string; name: string; updated: number; project: string; groupId: string; item: CatalogItem | null; draft: Conversation | null; family: ArtifactFamily | null; child?: boolean };
  const itemRow = (item: CatalogItem, family: ArtifactFamily | null, child = false): Row => ({ id: item.id, name: artifactTitle(item), updated: family ? Math.max(family.primary.modified_at, ...family.others.map((other) => other.modified_at)) : item.modified_at, project: projectName(item.project_id), groupId: snapshot.projects.some((project) => project.id === item.project_id) ? item.project_id! : "ungrouped", item, draft: null, family, child });
  const rows = sortRows<Row>([
    ...artifactFamilies(items, snapshot.artifact_groups).map((family) => itemRow(family.primary, family)),
    ...drafts.map((draft): Row => ({ id: draft.id, name: draftTitle(draft), updated: draft.updated_at, project: projectName(draft.draft_project_id), groupId: snapshot.projects.some((project) => project.id === draft.draft_project_id) ? draft.draft_project_id! : "ungrouped", item: null, draft, family: null })),
  ], sort);
  const renderRow = ({ id, name, updated, project, item, draft, family, child }: Row) => {
    const missing = !!item && snapshot.missing_sources?.includes(item.id);
    const available = !!item && snapshot.jobs.some((job) => belongsToScenario(job, item, snapshot) && job.status === "completed");
    const freshRun = item && snapshot.jobs.filter((job) => belongsToScenario(job, item, snapshot) && job.status === "completed" && generationIsCurrent(job, item, snapshot)).sort((a, b) => (b.started_at || b.created_at || 0) - (a.started_at || a.created_at || 0))[0];
    const actualSize = freshRun ? sizes[freshRun.id] : null;
    const validation = item && snapshot.validations[item.id];
    const forecast = validation && item && !["none", "stale"].includes(scenarioStates(item, snapshot)[0].state) ? validation.result.report?.resource_forecast as { final_output?: { expected_bytes?: number } } | undefined : undefined;
    const prediction = item ? currentPrediction(item, snapshot) : undefined;
    const estimatedSize = prediction?.result.forecast?.final_output.expected_bytes ?? forecast?.final_output?.expected_bytes;
    const drag = (event: DragEvent<HTMLElement>) => item ? onDragStart(event, item) : onDraftDragStart(event, draft!);
    const open = !!family && expandedFamilies.includes(family.key);
    return <li className={`scenario-row library-row-grid ${draft ? "scenario-draft" : ""} ${item?.hidden ? "scenario-hidden" : ""} ${child ? "family-member" : ""}`} key={id} draggable onDragStart={drag} onDragEnd={onDragEnd}>
      <span className="scenario-drag-handle col-drag" aria-hidden="true" title={`Drag ${name} to a project`} draggable onDragStart={(event) => { event.stopPropagation(); drag(event); }}><GripVertical size={14} /></span>
      <span className="col-expand">{family && family.others.length > 0 && <FamilyToggle name={name} count={family.others.length} open={open} onToggle={() => onToggleFamily(family.key, !open)} />}</span>
      <button className="scenario-open col-name" aria-label={`Open scenario ${name}`} onClick={() => item ? onOpen(item) : onOpenDraft(draft!)}>
        <span className={`scenario-symbol ${draft ? "draft" : ""}`}>{draft ? <PencilLine size={16} /> : <FileCode2 size={16} />}</span>
        <span className="scenario-row-copy">
          <span className="scenario-row-title"><strong title={name}>{name}</strong>{(item?.version || child) && <span className="scenario-version">{item?.version && item.version !== "Draft" ? item.version : "Draft"}</span>}{family && family.drafts > 0 && <DraftCount count={family.drafts} />}{item?.hidden && <span className="draft-chip">Hidden</span>}</span>
          <span className="scenario-description" title={item?.description}>{item ? snapshot.starter_drafts?.includes(item.id) ? "Ready to author" : item.description || "No description yet" : draft?.active ? "Authoring in progress" : "Ready to author"}</span>
          {item && <SearchExcerpts item={item} />}
        </span>
      </button>
      <span className="scenario-project col-project" title={`Project: ${project}`}><Folder size={13} aria-hidden="true" /><span>{project}</span></span>
      <div className="scenario-row-status col-status">{missing ? <StatusPill tone="err" label="Source missing" /> : item ? <ScenarioStatusPill item={item} snapshot={snapshot} /> : <StatusPill tone="neutral" label="Draft" detail="Not authored yet" />}</div>
      <span className="scenario-row-size col-size" title={actualSize != null ? "Measured size of the latest completed bundle for this revision" : estimatedSize != null ? "Estimated generated data size; actual output may differ" : "No current size estimate yet"}>{actualSize != null ? formatBundleSize(actualSize) : estimatedSize != null ? <>{formatBundleSize(estimatedSize)}<small>Estimated</small></> : "—"}</span>
      <time className="scenario-row-updated col-updated" dateTime={new Date(updated * 1000).toISOString()} title={new Date(updated * 1000).toLocaleString()}>{formatTime(updated)}</time>
      <div className="scenario-row-actions col-actions">{item ? <CatalogObjectMenu item={item} fallbackActions={[
        { id: "open", label: "Open", group: "inspect", run: () => onOpen(item) },
        { id: "properties", label: "Properties…", group: "locate", disabled: missing, reason: "Recover the missing source first", run: () => onProperties?.(item) },
        ...(missing ? [{ id: "recover", label: "Recover missing source…", group: "work" as const, run: () => onOpen(item) }] : []),
        { id: "clone", label: "Duplicate…", group: "manage", disabled: missing, reason: "Recover the missing source first", run: () => onClone(item) },
        { id: "export", label: "Export bundle…", group: "manage", disabled: !available, reason: "Complete a generation before exporting", run: () => onExport(item) },
        projectAssignmentAction(snapshot.projects, (projectId) => onMove(item, projectId), () => onNewProject(item)),
        { id: "hide", label: item.hidden ? "Show in library" : "Hide from library", group: "organize", run: () => onHide(item) },
        { id: "delete", label: "Delete scenario…", group: "remove", run: () => onDelete(item) },
      ]} /> : <DraftObjectMenu draft={draft!} projects={snapshot.projects} onOpen={() => onOpenDraft(draft!)} onRename={() => onRenameDraft(draft!)} onMove={(projectId) => onMoveDraft(draft!, projectId)} onDelete={() => onDeleteDraft(draft!)} />}</div>
    </li>;
  };
  const renderRows = (members: Row[]) => members.map((row) => <Fragment key={row.id}>
    {renderRow(row)}
    {row.family && expandedFamilies.includes(row.family.key) && row.family.others.map((other) => renderRow(itemRow(other, null, true)))}
  </Fragment>);
  return <LibraryTable label="Scenario library" className="scenario-table" columns={columns} sort={sort} onSort={onSort}>
    {groupRows(rows, sort).map((group) => <Fragment key={group.id || "all"}>
      {group.name && <LibraryGroupHeading name={group.name} count={group.rows.length} dropTarget={dropTargetId === group.id}
        onDragOver={(event) => onProjectDragOver(event, group.id === "ungrouped" ? null : group.id)} onDragLeave={onProjectDragLeave}
        onDrop={(event) => onProjectDrop(event, group.id === "ungrouped" ? null : group.id)} />}
      {renderRows(group.rows)}
    </Fragment>)}
  </LibraryTable>;
}

/** Expands a family row to list its other versions and drafts. */
export function FamilyToggle({ name, count, open, onToggle }: { name: string; count: number; open: boolean; onToggle: () => void }) {
  return <button type="button" className="family-toggle" aria-expanded={open} aria-label={`${open ? "Hide" : "Show"} ${count} other ${count === 1 ? "version" : "versions"} of ${name}`} title={`${count} other ${count === 1 ? "version" : "versions"}`} onClick={onToggle}>
    <ChevronRight size={13} aria-hidden="true" className={open ? "open" : ""} /><span>+{count}</span>
  </button>;
}

/** A collapsed family row's hint that it holds unpublished drafts (open them with the expander). */
export function DraftCount({ count }: { count: number }) {
  return <span className="draft-count" title={`${count} unpublished ${count === 1 ? "draft" : "drafts"}; expand the row to open ${count === 1 ? "it" : "them"}`}>{count} {count === 1 ? "draft" : "drafts"}</span>;
}
