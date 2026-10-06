import { MessageSquareText, MoreHorizontal } from "lucide-react";
import { DropdownMenu } from "radix-ui";
import type { Conversation } from "./api";
import { formatTime } from "./components";

export function ConversationList({ conversations, selectedId, onOpen, onRename, onDelete }: {
  conversations: Conversation[]; selectedId: string | null; onOpen: (chat: Conversation) => void;
  onRename: (chat: Conversation) => void; onDelete: (chat: Conversation) => void;
}) {
  return <div className="workspace-conversations">{conversations.map((chat) => <div className={`conversation-entry ${selectedId === chat.id ? "selected" : ""}`} key={chat.id}>
    <button className="conversation-row" aria-label={`Open ${chat.title}`} onClick={() => onOpen(chat)}><MessageSquareText size={17} /><span><strong>{chat.title}</strong><small>{chat.active ? chat.needs_attention ? "Needs input" : "Working" : formatTime(chat.updated_at)}</small></span>{chat.active && <span className={chat.needs_attention ? "attention-dot" : "active-pulse"} />}</button>
    <DropdownMenu.Root><DropdownMenu.Trigger className="icon-button conversation-menu-trigger" aria-label={`Options for ${chat.title}`}><MoreHorizontal size={16} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu" sideOffset={4}><DropdownMenu.Item onSelect={() => onRename(chat)}>Rename</DropdownMenu.Item><DropdownMenu.Item disabled={chat.active} onSelect={() => onDelete(chat)}>Delete</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>
  </div>)}</div>;
}
