import type { Conversation } from "./api";

/** Continue targets the first entry in this same visible, deterministic order. */
export function workspaceConversations(conversations: Conversation[], itemId: string): Conversation[] {
  return conversations.filter((chat) => chat.item_id === itemId).sort((left, right) =>
    right.updated_at - left.updated_at || left.id.localeCompare(right.id));
}
