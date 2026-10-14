import type { StudioEvent } from "./api";

export interface TimelineItem {
  id: string; type: string; text?: string; phase?: string | null; status?: string;
  content?: { type: string; text?: string }[]; clientId?: string | null;
  summary?: string[]; aggregatedOutput?: string; [key: string]: unknown;
}
export interface TimelineResult {
  id: string; path: string; kind?: string; diff?: string | null; item_id?: string | null; item_kind?: string | null;
  operation?: "edited" | "created" | "removed" | "renamed" | "changed"; relative_path?: string;
  previous_path?: string | null; previous_relative_path?: string | null; available?: boolean;
  lines_added?: number | null; lines_removed?: number | null; current_lines?: number | null;
  current_characters?: number | null; current_bytes?: number | null; metadata_only?: boolean;
}
export interface TimelineTurn {
  id: string; status: string; items: TimelineItem[]; started_at?: number | null;
  completed_at?: number | null; duration_ms?: number | null; error?: { message?: string } | null;
  results?: TimelineResult[];
}
export const terminalTurn = (turn: TimelineTurn) => ["completed", "failed", "interrupted"].includes(turn.status);

export function upsertItem(items: TimelineItem[], item: TimelineItem): TimelineItem[] {
  const index = items.findIndex((entry) => entry.id === item.id ||
    (item.type === "userMessage" && item.clientId && entry.clientId === item.clientId));
  return index < 0 ? [...items, item] : items.map((entry, position) => position === index ? { ...entry, ...item } : entry);
}

export function historyTurns(history: { thread?: { turns?: Record<string, unknown>[] } }): TimelineTurn[] {
  return (history.thread?.turns || []).map((turn, index) => ({
    id: String(turn.id || `history-${index}`), status: String(turn.status || "completed"),
    started_at: typeof turn.startedAt === "number" ? turn.startedAt : null,
    completed_at: typeof turn.completedAt === "number" ? turn.completedAt : null,
    duration_ms: typeof turn.durationMs === "number" ? turn.durationMs : null,
    error: turn.error as TimelineTurn["error"],
    items: ((turn.items || []) as TimelineItem[]).map((item, position) => ({ ...item, id: item.id || `${turn.id || index}-item-${position}` })),
  }));
}

export function mergeTurns(saved: TimelineTurn[], live: TimelineTurn[]): TimelineTurn[] {
  const merged = saved.map((turn) => {
    const current = live.find((entry) => entry.id === turn.id);
    if (!current || terminalTurn(turn)) return turn;
    return { ...turn, ...current, items: current.items.reduce(upsertItem, turn.items) };
  });
  return [...merged, ...live.filter((turn) => !saved.some((entry) => entry.id === turn.id))];
}

export function applyChatEvent(turns: TimelineTurn[], event: StudioEvent): TimelineTurn[] {
  const method = String(event.payload.method || "");
  const params = (event.payload.params || {}) as Record<string, unknown>;
  const native = params.turn as Record<string, unknown> | undefined;
  const turnId = typeof native?.id === "string" ? native.id : typeof params.turnId === "string" ? params.turnId :
    [...turns].reverse().find((turn) => !terminalTurn(turn))?.id || (method.startsWith("item/") ? "pending-turn" : undefined);
  if (!turnId) return turns;
  let turn = turns.find((entry) => entry.id === turnId) || { id: turnId, status: "inProgress", items: [], started_at: Date.now() / 1000 };
  turn = { ...turn, items: [...turn.items] };
  if (method === "turn/started") {
    if (typeof native?.startedAt === "number") turn.started_at = native.startedAt;
  } else if (method === "turn/completed") {
    turn.status = String(native?.status || "completed");
    turn.error = native?.error as TimelineTurn["error"] || turn.error;
    turn.completed_at = typeof native?.completedAt === "number" ? native.completedAt : Date.now() / 1000;
    turn.duration_ms = typeof native?.durationMs === "number" ? native.durationMs : Math.max(0, (turn.completed_at - (turn.started_at || turn.completed_at)) * 1000);
  } else if (method === "item/started" || method === "item/completed") {
    const item = params.item as TimelineItem | undefined;
    if (item?.id) turn.items = upsertItem(turn.items, { ...item, status: item.status || (method === "item/completed" ? "completed" : "inProgress") });
  } else if (method === "item/agentMessage/delta") {
    const id = String(params.itemId || `legacy-agent-${turnId}`);
    const item = turn.items.find((entry) => entry.id === id) || { id, type: "agentMessage", status: "inProgress" };
    turn.items = upsertItem(turn.items, { ...item, text: (item.text || "") + String(params.delta || "") });
  } else if (method === "item/reasoning/summaryTextDelta" || method === "item/commandExecution/outputDelta") {
    const id = String(params.itemId || "");
    if (id) {
      const item = turn.items.find((entry) => entry.id === id) || { id, type: method.includes("reasoning") ? "reasoning" : "commandExecution", status: "inProgress" };
      if (method.includes("reasoning")) {
        const summary = [...(item.summary || [])]; const index = Number(params.summaryIndex || 0);
        if (index >= 0 && index <= 100) { summary[index] = (summary[index] || "") + String(params.delta || ""); turn.items = upsertItem(turn.items, { ...item, summary }); }
      } else turn.items = upsertItem(turn.items, { ...item, aggregatedOutput: ((item.aggregatedOutput || "") + String(params.delta || "")).slice(-262144) });
    }
  } else if (method === "error" && params.willRetry === false) turn.error = params.error as TimelineTurn["error"];
  return turns.some((entry) => entry.id === turnId) ? turns.map((entry) => entry.id === turnId ? turn : entry) : [...turns, turn];
}

export function finalItemId(turn: TimelineTurn): string | undefined {
  const explicit = [...turn.items].reverse().find((item) => item.type === "agentMessage" && item.phase === "final_answer" && item.text);
  if (explicit) return explicit.id;
  if (turn.status !== "completed") return undefined;
  return [...turn.items].reverse().find((item) => item.type === "agentMessage" && !item.phase && item.text)?.id;
}

export function formatDuration(milliseconds: number): string {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return minutes < 60 ? `${minutes}m ${seconds % 60}s` : `${Math.floor(minutes / 60)}h ${minutes % 60}m ${seconds % 60}s`;
}
