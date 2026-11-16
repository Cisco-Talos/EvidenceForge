import { belongsToScenario } from "./scenarioSources";
import { artifactTitle, draftTitle } from "./artifactNaming";
import { artifactGroup, artifactGroupLabel } from "./artifactGrouping";
import { Fragment, type DragEvent, useEffect, useState } from "react";
import { FileCode2, Folder, GripVertical, PencilLine } from "lucide-react";
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
  { key: "drag", label: "" }, { key: "name", label: "Name", sort: "name" }, { key: "project", label: "Project", sort: "project" },
  { key: "status", label: "Status" }, { key: "size", label: "Size" }, { key: "updated", label: "Updated", sort: "updated" }, { key: "actions", label: "" },
];

export function ScenarioLibrary({ items, drafts, snapshot, api, sort, onSort, onOpen, onProperties, onOpenDraft, onClone,
  onExport, onHide, onDelete, onMove, onMoveDraft, onNewProject, onRenameDraft,
  onDeleteDraft, onDragStart, onDraftDragStart, onDragEnd, dropTargetId, onProjectDragOver, onProjectDragLeave, onProjectDrop }: {
  dropTargetId: string | null;
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
  const rows = sortRows([
    ...items.map((item) => ({ id: item.id, name: artifactTitle(item), updated: item.modified_at, project: projectName(item.project_id), groupId: snapshot.projects.some((project) => project.id === item.project_id) ? item.project_id! : "ungrouped", item, draft: null })),
    ...drafts.map((draft) => ({ id: draft.id, name: draftTitle(draft), updated: draft.updated_at, project: projectName(draft.draft_project_id), groupId: snapshot.projects.some((project) => project.id === draft.draft_project_id) ? draft.draft_project_id! : "ungrouped", item: null, draft })),
  ], sort);
  const renderRow = ({ id, name, updated, project, item, draft }: typeof rows[number]) => {
    const missing = !!item && snapshot.missing_sources?.includes(item.id);
    const available = !!item && snapshot.jobs.some((job) => belongsToScenario(job, item, snapshot) && job.status === "completed");
    const freshRun = item && snapshot.jobs.filter((job) => belongsToScenario(job, item, snapshot) && job.status === "completed" && generationIsCurrent(job, item, snapshot)).sort((a, b) => (b.started_at || b.created_at || 0) - (a.started_at || a.created_at || 0))[0];
    const actualSize = freshRun ? sizes[freshRun.id] : null;
    const validation = item && snapshot.validations[item.id];
    const forecast = validation && item && !["none", "stale"].includes(scenarioStates(item, snapshot)[0].state) ? validation.result.report?.resource_forecast as { final_output?: { expected_bytes?: number } } | undefined : undefined;
    const prediction = item ? currentPrediction(item, snapshot) : undefined;
    const estimatedSize = prediction?.result.forecast?.final_output.expected_bytes ?? forecast?.final_output?.expected_bytes;
    const drag = (event: DragEvent<HTMLElement>) => item ? onDragStart(event, item) : onDraftDragStart(event, draft!);
    return <li className={`scenario-row library-row-grid ${draft ? "scenario-draft" : ""} ${item?.hidden ? "scenario-hidden" : ""}`} key={id} draggable onDragStart={drag} onDragEnd={onDragEnd}>
      <span className="scenario-drag-handle col-drag" aria-hidden="true" title={`Drag ${name} to a project`} draggable onDragStart={(event) => { event.stopPropagation(); drag(event); }}><GripVertical size={14} /></span>
      <button className="scenario-open col-name" aria-label={`Open scenario ${name}`} onClick={() => item ? onOpen(item) : onOpenDraft(draft!)}>
        <span className={`scenario-symbol ${draft ? "draft" : ""}`}>{draft ? <PencilLine size={16} /> : <FileCode2 size={16} />}</span>
        <span className="scenario-row-copy">
          <span className="scenario-row-title"><strong title={name}>{name}</strong>{item?.version && <span className="scenario-version">{item.version}</span>}{item?.hidden && <span className="draft-chip">Hidden</span>}</span>
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
  const renderRows = (members: typeof rows) => [...new Set(members.map((row) => row.item ? artifactGroup(row.item, snapshot.artifact_groups).key : row.id))].map((identity) => {
    const family = members.filter((row) => (row.item ? artifactGroup(row.item, snapshot.artifact_groups).key : row.id) === identity);
    const group = family[0].item ? artifactGroup(family[0].item, snapshot.artifact_groups) : null;
    const duplicateName = members.some((row) => row.item && group && row.item.name === group.name && artifactGroup(row.item, snapshot.artifact_groups).key !== identity);
    return <Fragment key={identity}>{group && (family.length > 1 || duplicateName) && <li className="artifact-identity-heading">{artifactGroupLabel(group)}{family.length > 1 ? " · drafts & releases" : ""}</li>}{family.map(renderRow)}</Fragment>;
  });
  return <LibraryTable label="Scenario library" className="scenario-table" columns={columns} sort={sort} onSort={onSort}>
    {groupRows(rows, sort).map((group) => <Fragment key={group.id || "all"}>
      {group.name && <LibraryGroupHeading name={group.name} count={group.rows.length} dropTarget={dropTargetId === group.id}
        onDragOver={(event) => onProjectDragOver(event, group.id === "ungrouped" ? null : group.id)} onDragLeave={onProjectDragLeave}
        onDrop={(event) => onProjectDrop(event, group.id === "ungrouped" ? null : group.id)} />}
      {renderRows(group.rows)}
    </Fragment>)}
  </LibraryTable>;
}
