import { SearchExcerpts } from "./SearchExcerpts";
import type { DragEvent } from "react";
import { ArrowUpRight, ChevronRight, Check, Copy, Download, Folder, GripVertical, Layers3, MoreHorizontal, Plus, SquarePen } from "lucide-react";
import { DropdownMenu } from "radix-ui";
import type { CatalogItem, Conversation, Project } from "./api";
import { formatTime } from "./components";
import { countLabel } from "./workspaceSummaries";
import { HeaderSummary } from "./WorkspaceSection";

type PackKind = "industry_pack" | "organization_pack";

export function ProjectPicker({ name, projectId, projects, onMove, onNewProject }: {
  name: string; projectId: string | null; projects: Project[];
  onMove: (projectId: string | null) => void; onNewProject?: () => void;
}) {
  return <DropdownMenu.Root><DropdownMenu.Trigger className="icon-button" aria-label={`Move ${name} to project`} title="Move to project"><Folder size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu project-assignment-menu" sideOffset={4} align="end"><DropdownMenu.Label>Move to project</DropdownMenu.Label><DropdownMenu.Item onSelect={() => onMove(null)}>{!projectId && <Check size={14} />} Ungrouped</DropdownMenu.Item>{projects.map((project) => <DropdownMenu.Item key={project.id} onSelect={() => onMove(project.id)}>{projectId === project.id && <Check size={14} />} {project.name}</DropdownMenu.Item>)}{onNewProject && <><DropdownMenu.Separator /><DropdownMenu.Item onSelect={onNewProject}><Plus size={14} />New project…</DropdownMenu.Item></>}</DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>;
}

export function PackLibrary({ items, drafts, projects, busy, onOpen, onOpenDraft, onNew, onClone, onExport, onHide, onMove, onMoveDraft, onNewProject, onDeleteDraft, onDragStart, onDraftDragStart, onDragEnd, expandedGroups, onToggleGroup }: {
  expandedGroups: string[]; onToggleGroup: (id: string, open: boolean) => void;
  items: CatalogItem[]; drafts: Conversation[]; projects: Project[]; busy: boolean;
  onOpen: (item: CatalogItem) => void; onOpenDraft: (draft: Conversation) => void;
  onNew: (kind: PackKind) => void; onClone: (item: CatalogItem) => void; onExport: (item: CatalogItem) => void;
  onHide: (item: CatalogItem) => void; onMove: (item: CatalogItem, projectId: string | null) => void;
  onMoveDraft: (draft: Conversation, projectId: string | null) => void;
  onNewProject: (item: CatalogItem) => void; onDeleteDraft: (draft: Conversation) => void;
  onDragStart: (event: DragEvent<HTMLElement>, item: CatalogItem) => void;
  onDraftDragStart: (event: DragEvent<HTMLElement>, draft: Conversation) => void; onDragEnd: () => void;
}) {
  const projectName = (id: string | null) => projects.find((project) => project.id === id)?.name || "Ungrouped";
  return <div className="job-sections pack-sections">{(["industry_pack", "organization_pack"] as PackKind[]).map((kind) => {
    const packs = items.filter((item) => item.kind === kind).sort((a, b) => a.name.localeCompare(b.name) || (a.publisher || "").localeCompare(b.publisher || "") || a.version.localeCompare(b.version) || a.id.localeCompare(b.id));
    const pending = drafts.filter((draft) => draft.draft_kind === kind);
    const authors = [...new Set(packs.map((pack) => pack.publisher_display_name || pack.publisher || "Unknown author"))];
    const updated = Math.max(0, ...packs.map((pack) => pack.modified_at), ...pending.map((draft) => draft.updated_at));
    const title = kind === "industry_pack" ? "Industry packs" : "Organization packs";
    return <details className="job-group pack-group" key={kind} open={expandedGroups.includes(kind)} onToggle={(event) => onToggleGroup(kind, event.currentTarget.open)}>
      <summary><ChevronRight size={17} className="disclosure-chevron" /><strong>{title}</strong><span>{packs.length + pending.length}</span><small className="group-summary"><HeaderSummary summary={{ headline: [countLabel(packs.length, "available pack"), pending.length && countLabel(pending.length, "draft"), pending.some((draft) => draft.active) && `${pending.filter((draft) => draft.active).length} authoring`].filter(Boolean).join(" · "), detail: [authors.slice(0, 2).join(", "), authors.length > 2 && `${authors.length - 2} more authors`, updated && `Updated ${formatTime(updated)}`].filter(Boolean).join(" · ") }} /></small><button className="button-quiet pack-new" aria-label={`New ${kind === "industry_pack" ? "industry" : "organization"} pack`} disabled={busy} onClick={(event) => { event.preventDefault(); event.stopPropagation(); onNew(kind); }}><Plus size={14} /> New</button></summary>
      <div className="pack-list">
        {pending.map((draft) => <div className="pack-row pack-draft" key={draft.id} draggable onDragStart={(event) => onDraftDragStart(event, draft)} onDragEnd={onDragEnd}><button className="pack-open" onClick={() => onOpenDraft(draft)}><SquarePen size={18} /><span className="pack-row-copy"><strong>{draft.draft_name || draft.title}</strong><small>{draft.active ? "Authoring in progress" : "Ready to author"} · {projectName(draft.draft_project_id)}</small></span><span className="draft-chip">Draft</span></button><ProjectPicker name={draft.draft_name || draft.title} projectId={draft.draft_project_id} projects={projects} onMove={(id) => onMoveDraft(draft, id)} /><DropdownMenu.Root><DropdownMenu.Trigger className="icon-button" aria-label={`Options for ${draft.title}`}><MoreHorizontal size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={4}><DropdownMenu.Item disabled={draft.active} onSelect={() => onDeleteDraft(draft)}>Delete draft</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root></div>)}
        {packs.map((item) => <div className={`pack-row draggable-pack ${item.hidden ? "hidden-pack" : ""}`} key={item.id} draggable onDragStart={(event) => onDragStart(event, item)} onDragEnd={onDragEnd}>
          <span className="pack-drag-handle" aria-hidden="true" title={`Drag ${item.name} to a project`} draggable onDragStart={(event) => { event.stopPropagation(); onDragStart(event, item); }}><GripVertical size={14} /></span>
          <button className="pack-open" aria-label={`Open ${item.name} ${item.version}`} onClick={() => onOpen(item)}><Layers3 size={18} /><span className="pack-row-copy"><strong>{item.name}</strong><small title={item.description}>{item.description || "No description yet"}</small><SearchExcerpts item={item} /><small className="pack-row-meta"><span title={`Publisher: ${item.publisher || "not recorded"}`}>By {item.publisher_display_name || item.publisher || "Unknown author"}</span><span>·</span><span title={item.pack_source === "bundled" ? "Included with EvidenceForge" : "Authored or imported in this workspace"}>{item.pack_source === "bundled" ? "Bundled" : "Workspace"}</span><span>·</span><span>{projectName(item.project_id)}</span>{item.hidden && <><span>·</span><span>Hidden</span></>}</small></span><span className="pack-version">{item.version || "YAML"}</span><time title={new Date(item.modified_at * 1000).toLocaleString()}>{formatTime(item.modified_at)}</time><ArrowUpRight size={16} /></button>
          <ProjectPicker name={item.name} projectId={item.project_id} projects={projects} onMove={(id) => onMove(item, id)} onNewProject={() => onNewProject(item)} />
          <DropdownMenu.Root><DropdownMenu.Trigger className="icon-button" aria-label={`Options for ${item.name} ${item.version}`}><MoreHorizontal size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={4} align="end"><DropdownMenu.Item onSelect={() => onExport(item)}><Download size={14} /> Export pack…</DropdownMenu.Item><DropdownMenu.Item onSelect={() => onClone(item)}><Copy size={14} /> Clone pack…</DropdownMenu.Item><DropdownMenu.Item onSelect={() => onHide(item)}>{item.hidden ? "Unhide" : "Hide"}</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>
        </div>)}
        {!packs.length && !pending.length && <p className="muted job-group-empty">No {title.toLowerCase()} match this view.</p>}
      </div>
    </details>;
  })}</div>;
}
