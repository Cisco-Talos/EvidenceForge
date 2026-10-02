import { type DragEvent, useEffect, useState } from "react";
import { ChevronRight, Copy, Download, FileCode2, Folder, GripVertical, MoreHorizontal, SquarePen } from "lucide-react";
import { DropdownMenu } from "radix-ui";
import { isTauri } from "@tauri-apps/api/core";
import type { CatalogItem, Conversation, Project, StudioApi, StudioSnapshot } from "./api";
import { formatBundleSize, formatTime } from "./components";
import { ProjectPicker } from "./PackLibrary";
import { ScenarioStates, scenarioStates } from "./ScenarioStates";

import { SearchExcerpts } from "./SearchExcerpts";
import { generationIsCurrent } from "./ScenarioStates";
import { currentPrediction } from "./ResourceForecastPanel";

export type ScenarioSort = "name" | "updated" | "project";

export function ScenarioLibrary({ items, drafts, snapshot, api, sort, onOpen, onOpenDraft, onClone,
  onExport, onUnavailableExport, onHide, onMove, onMoveDraft, onNewProject, onRenameDraft,
  onDeleteDraft, onDragStart, onDraftDragStart, onDragEnd, expandedGroups, onToggleGroup, dropTargetId, onProjectDragOver, onProjectDragLeave, onProjectDrop }: {
  expandedGroups: string[]; onToggleGroup: (id: string, open: boolean) => void;
  dropTargetId: string | null;
  onProjectDragOver: (event: DragEvent<HTMLElement>, projectId: string | null) => void;
  onProjectDragLeave: (event: DragEvent<HTMLElement>) => void;
  onProjectDrop: (event: DragEvent<HTMLElement>, projectId: string | null) => void;
  items: CatalogItem[]; drafts: Conversation[]; snapshot: StudioSnapshot; api: StudioApi; sort: ScenarioSort;
  onOpen: (item: CatalogItem) => void; onOpenDraft: (draft: Conversation) => void;
  onClone: (item: CatalogItem) => void; onExport: (item: CatalogItem) => void;
  onUnavailableExport: () => void; onHide: (item: CatalogItem) => void;
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
  const rows = [
    ...items.map((item) => ({ id: item.id, name: item.name, updated: item.modified_at, project: projectName(item.project_id), groupId: snapshot.projects.some((project) => project.id === item.project_id) ? item.project_id! : "ungrouped", item, draft: null })),
    ...drafts.map((draft) => ({ id: draft.id, name: draft.draft_name || draft.title, updated: draft.updated_at, project: projectName(draft.draft_project_id), groupId: snapshot.projects.some((project) => project.id === draft.draft_project_id) ? draft.draft_project_id! : "ungrouped", item: null, draft })),
  ].sort((a, b) => (sort === "updated" ? b.updated - a.updated : sort === "project" ? a.project.localeCompare(b.project) : 0) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  const renderRow = ({ id, name, updated, project, item, draft }: typeof rows[number]) => {
    const available = !!item && snapshot.jobs.some((job) => job.kind === "generation" && job.scenario === item.path && job.status === "completed");
    const freshRun = item && snapshot.jobs.filter((job) => job.kind === "generation" && job.scenario === item.path && job.status === "completed" && generationIsCurrent(job, item, snapshot)).sort((a, b) => (b.started_at || b.created_at || 0) - (a.started_at || a.created_at || 0))[0];
    const actualSize = freshRun ? sizes[freshRun.id] : null;
    const validation = item && snapshot.validations[item.id];
    const forecast = validation && item && !["none", "stale"].includes(scenarioStates(item, snapshot)[0].state) ? validation.result.report?.resource_forecast as { final_output?: { expected_bytes?: number } } | undefined : undefined;
    const prediction = item ? currentPrediction(item, snapshot) : undefined;
    const estimatedSize = prediction?.result.forecast?.final_output.expected_bytes ?? forecast?.final_output?.expected_bytes;
    const drag = (event: DragEvent<HTMLElement>) => item ? onDragStart(event, item) : onDraftDragStart(event, draft!);
    return <li className={`scenario-row ${draft ? "scenario-draft" : ""} ${item?.hidden ? "scenario-hidden" : ""}`} key={id} draggable onDragStart={drag} onDragEnd={onDragEnd}>
      <span className="scenario-drag-handle" aria-hidden="true" title={`Drag ${name} to a project`} draggable onDragStart={(event) => { event.stopPropagation(); drag(event); }}><GripVertical size={14} /></span>
      <button className="scenario-open" aria-label={`Open scenario ${name}`} onClick={() => item ? onOpen(item) : onOpenDraft(draft!)}>
        <span className="scenario-symbol">{item ? <FileCode2 size={18} /> : <SquarePen size={18} />}</span>
        <span className="scenario-row-copy">
          <span className="scenario-row-title"><strong title={name}>{name}</strong><span className="scenario-project" title={`Project: ${project}`}><Folder size={12} /><span>{project}</span></span>{draft && <span className="draft-chip">Draft</span>}{item?.hidden && <span className="draft-chip">Hidden</span>}</span>
          <span className="scenario-description" title={item?.description}>{item ? item.description || "No description yet" : draft?.active ? "Authoring in progress" : "Ready to author"}</span>
          {item && <SearchExcerpts item={item} />}
          <span className="scenario-mobile-meta">{item?.version || "Not authored yet"} · Updated {formatTime(updated)}</span>
        </span>
      </button>
      <div className="scenario-row-status">{item ? <ScenarioStates item={item} snapshot={snapshot} compact /> : <span className="muted">Not authored yet</span>}</div>
      <span className="scenario-row-size" title={actualSize != null ? "Measured size of the latest completed bundle for this revision" : estimatedSize != null ? "Estimated generated data size; actual output may differ" : "No current size estimate yet"}>{actualSize != null ? formatBundleSize(actualSize) : estimatedSize != null ? <>{formatBundleSize(estimatedSize)}<small>Estimated</small></> : "—"}</span>
      <div className="scenario-row-meta"><span>{item?.version || "Draft"}</span><time dateTime={new Date(updated * 1000).toISOString()} title={new Date(updated * 1000).toLocaleString()}>{formatTime(updated)}</time></div>
      <div className="scenario-row-actions">
        <ProjectPicker name={name} projectId={item ? item.project_id : draft!.draft_project_id} projects={snapshot.projects} onMove={(projectId) => item ? onMove(item, projectId) : onMoveDraft(draft!, projectId)} onNewProject={item ? () => onNewProject(item) : undefined} />
        {item && <button className={`icon-button ${available ? "" : "unavailable"}`} aria-label={`${isTauri() ? "Export" : "Download"} bundle for ${name}`} title={available ? "Export a completed run" : "Generate a run before exporting"} onClick={() => available ? onExport(item) : onUnavailableExport()}><Download size={16} /></button>}
        <DropdownMenu.Root><DropdownMenu.Trigger className="icon-button" aria-label={`Options for ${name}`} title="More options"><MoreHorizontal size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={4} align="end">{item ? <><DropdownMenu.Item onSelect={() => onClone(item)}><Copy size={14} /> Clone scenario…</DropdownMenu.Item><DropdownMenu.Item onSelect={() => onHide(item)}>{item.hidden ? "Unhide" : "Hide"}</DropdownMenu.Item></> : <><DropdownMenu.Item onSelect={() => onRenameDraft(draft!)}>Rename scenario</DropdownMenu.Item><DropdownMenu.Item disabled={draft!.active} onSelect={() => onDeleteDraft(draft!)}>Delete draft</DropdownMenu.Item></>}</DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>
      </div>
    </li>;
  };
  const grouped = new Map<string, { id: string; name: string; updated: number; rows: typeof rows }>();
  for (const row of rows) {
    const group = grouped.get(row.groupId) || { id: row.groupId, name: row.project, updated: 0, rows: [] };
    group.rows.push(row);
    group.updated = Math.max(group.updated, row.updated);
    grouped.set(row.groupId, group);
  }
  const groups = [...grouped.values()].sort((a, b) => (sort === "updated" ? b.updated - a.updated : 0) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  return <div className="scenario-groups" aria-label="Scenario library">{groups.map((group) => <details className={`job-group scenario-group ${dropTargetId === group.id ? "drop-target" : ""}`} key={group.id} open={expandedGroups.includes(group.id)} onToggle={(event) => onToggleGroup(group.id, event.currentTarget.open)} onDragOver={(event) => onProjectDragOver(event, group.id === "ungrouped" ? null : group.id)} onDragLeave={onProjectDragLeave} onDrop={(event) => onProjectDrop(event, group.id === "ungrouped" ? null : group.id)}>
    <summary aria-label={`${group.name} · ${group.rows.length} scenario${group.rows.length === 1 ? "" : "s"}`}><ChevronRight size={17} className="disclosure-chevron" /><Folder size={16} /><strong>{group.name}</strong><span>{group.rows.length}</span></summary>
    <ul className="scenario-list" aria-label={`Scenarios in ${group.name}`}>{group.rows.map(renderRow)}</ul>
  </details>)}</div>;
}
