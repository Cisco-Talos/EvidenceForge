import { MessageSquareText } from "lucide-react";
import { ObjectMenu, type ObjectAction } from "./ObjectActions";
import type { Conversation } from "./api";
import { formatTime } from "./components";

export function conversationActions(chat: Conversation, onOpen: (chat: Conversation) => void, onRename: (chat: Conversation) => void, onDelete: (chat: Conversation) => void): ObjectAction[] {
  return [
    { id: "open", label: "Open", group: "inspect", run: () => onOpen(chat) },
    { id: "rename", label: "Rename…", group: "organize", run: () => onRename(chat) },
    { id: "delete", label: "Delete conversation", group: "remove", disabled: chat.active, reason: "Finish or stop the active turn first", description: "Remove the Studio entry; keep authored files and the Codex thread", run: () => onDelete(chat) },
  ];
}

export function ConversationList({ conversations, selectedId, onOpen, onRename, onDelete }: {
  conversations: Conversation[]; selectedId: string | null; onOpen: (chat: Conversation) => void;
  onRename: (chat: Conversation) => void; onDelete: (chat: Conversation) => void;
}) {
  return <div className="workspace-conversations">{conversations.map((chat) => <div className={`conversation-entry ${selectedId === chat.id ? "selected" : ""}`} key={chat.id}>
    <button className="conversation-row" aria-label={`Open ${chat.title}`} onClick={() => onOpen(chat)}><MessageSquareText size={17} /><span><strong>{chat.title}</strong><small>{chat.active ? chat.needs_attention ? "Needs input" : "Working" : formatTime(chat.updated_at)}</small></span>{chat.active && <span className={chat.needs_attention ? "attention-dot" : "active-pulse"} />}</button>
    <ObjectMenu label={`Options for ${chat.title}`} className="conversation-menu-trigger" actions={conversationActions(chat, onOpen, onRename, onDelete)} />
  </div>)}</div>;
}
