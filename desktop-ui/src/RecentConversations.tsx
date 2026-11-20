import { useLayoutEffect, useRef, useState } from "react";
import { MessageSquareText } from "lucide-react";
import type { Conversation } from "./api";
import { formatTime } from "./components";

/** Height of one row in CSS pixels; keep in sync with `.recent-conversation` in App.css. */
const ROW_HEIGHT = 32;

/**
 * The newest conversations, as many as fit in the space an Overview card has left over. Each row
 * opens its conversation directly. The list never sets the card's height: equal-height cards decide
 * it, and the list fills whatever remains.
 */
export function RecentConversations({ conversations, onOpen }: { conversations: Conversation[]; onOpen: (chat: Conversation) => void }) {
  const area = useRef<HTMLDivElement>(null);
  const [fits, setFits] = useState(3);
  useLayoutEffect(() => {
    const element = area.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => setFits(Math.max(1, Math.floor(entry.contentRect.height / ROW_HEIGHT))));
    observer.observe(element);
    return () => observer.disconnect();
  }, [conversations.length > 0]);
  if (!conversations.length) return null;
  return <div className="recent-conversations" ref={area}>
    <ul aria-label="Recent conversations">{conversations.slice(0, fits).map((chat) => <li key={chat.id}>
      <button type="button" className="recent-conversation" aria-label={`Open ${chat.title}`} onClick={() => onOpen(chat)}>
        <MessageSquareText size={14} aria-hidden="true" /><span>{chat.title}</span>
        {chat.needs_attention ? <em>Needs input</em> : chat.active ? <em>Working</em> : null}
        <time dateTime={new Date((chat.updated_at || 0) * 1000).toISOString()}>{formatTime(chat.updated_at || 0)}</time>
      </button>
    </li>)}</ul>
  </div>;
}
