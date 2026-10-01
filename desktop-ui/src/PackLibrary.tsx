import { ArrowUpRight, Check, Copy, FolderOpen, Layers3, MoreHorizontal, Plus, SquarePen } from "lucide-react";
import { DropdownMenu } from "radix-ui";
import type { CatalogItem, Conversation } from "./api";
import { formatTime } from "./components";

type PackKind = "industry_pack" | "organization_pack";

export function PackLibrary({ items, drafts, folders, busy, onOpen, onOpenDraft, onNew, onClone, onHide, onMove, onNewFolder, onDeleteDraft }: {
  items: CatalogItem[]; drafts: Conversation[]; folders: string[]; busy: boolean;
  onOpen: (item: CatalogItem) => void; onOpenDraft: (draft: Conversation) => void;
  onNew: (kind: PackKind) => void; onClone: (item: CatalogItem) => void;
  onHide: (item: CatalogItem) => void; onMove: (item: CatalogItem, folder: string | null) => void;
  onNewFolder: (item: CatalogItem) => void; onDeleteDraft: (draft: Conversation) => void;
}) {
  return <div className="job-sections pack-sections">{(["industry_pack", "organization_pack"] as PackKind[]).map((kind) => {
    const packs = items.filter((item) => item.kind === kind).sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version) || a.id.localeCompare(b.id));
    const pending = drafts.filter((draft) => draft.draft_kind === kind);
    const title = kind === "industry_pack" ? "Industry packs" : "Organization packs";
    return <details className="job-group pack-group" key={kind} open>
      <summary><strong>{title}</strong><span>{packs.length + pending.length}</span><button className="button-quiet pack-new" aria-label={`New ${kind === "industry_pack" ? "industry" : "organization"} pack`} disabled={busy} onClick={(event) => { event.preventDefault(); event.stopPropagation(); onNew(kind); }}><Plus size={14} /> New</button></summary>
      <div className="pack-list">
        {pending.map((draft) => <div className="pack-row pack-draft" key={draft.id}><button className="pack-open" onClick={() => onOpenDraft(draft)}><SquarePen size={18} /><span className="pack-row-copy"><strong>{draft.draft_name || draft.title}</strong><small>{draft.active ? "Authoring in progress" : "Ready to author"}</small></span><span className="draft-chip">Draft</span></button><DropdownMenu.Root><DropdownMenu.Trigger className="icon-button" aria-label={`Options for ${draft.title}`}><MoreHorizontal size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={4}><DropdownMenu.Item disabled={draft.active} onSelect={() => onDeleteDraft(draft)}>Delete draft</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root></div>)}
        {packs.map((item) => <div className={`pack-row ${item.hidden ? "hidden-pack" : ""}`} key={item.id}>
          <button className="pack-open" aria-label={`Open ${item.name} ${item.version}`} onClick={() => onOpen(item)}><Layers3 size={18} /><span className="pack-row-copy"><strong>{item.name}</strong><small title={item.description}>{item.description || "No description yet"}</small>{(item.folder || item.hidden) && <small className="pack-row-folder">{item.folder && <><FolderOpen size={12} /> {item.folder}</>}{item.hidden && <span>Hidden</span>}</small>}</span><span className="pack-version">{item.version || "YAML"}</span><time title={new Date(item.modified_at * 1000).toLocaleString()}>{formatTime(item.modified_at)}</time><ArrowUpRight size={16} /></button>
          <DropdownMenu.Root><DropdownMenu.Trigger className="icon-button" aria-label={`Options for ${item.name} ${item.version}`}><MoreHorizontal size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={4} align="end"><DropdownMenu.Item onSelect={() => onClone(item)}><Copy size={14} /> Clone pack…</DropdownMenu.Item><DropdownMenu.Sub><DropdownMenu.SubTrigger>Move to folder</DropdownMenu.SubTrigger><DropdownMenu.Portal><DropdownMenu.SubContent className="conversation-menu" sideOffset={5}><DropdownMenu.Item onSelect={() => onMove(item, null)}>{!item.folder && <Check size={14} />} No folder</DropdownMenu.Item>{folders.map((folder) => <DropdownMenu.Item key={folder} onSelect={() => onMove(item, folder)}>{item.folder === folder && <Check size={14} />} {folder}</DropdownMenu.Item>)}<DropdownMenu.Item onSelect={() => onNewFolder(item)}><Plus size={14} /> New folder…</DropdownMenu.Item></DropdownMenu.SubContent></DropdownMenu.Portal></DropdownMenu.Sub><DropdownMenu.Item onSelect={() => onHide(item)}>{item.hidden ? "Unhide" : "Hide"}</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>
        </div>)}
        {!packs.length && !pending.length && <p className="muted job-group-empty">No {title.toLowerCase()} match this view.</p>}
      </div>
    </details>;
  })}</div>;
}
