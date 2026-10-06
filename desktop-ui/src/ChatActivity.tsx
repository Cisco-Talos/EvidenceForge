import { ChevronDown } from "lucide-react";
import { ChatMarkdown } from "./ChatMarkdown";

export interface ActivityItem {
  type: string;
  id?: string;
  status?: string;
  command?: string;
  cwd?: string;
  aggregatedOutput?: string | null;
  summary?: string[];
  changes?: { path: string; diff?: string }[];
  text?: string;
  [key: string]: unknown;
}

export function upsertActivity(items: ActivityItem[], item: ActivityItem): ActivityItem[] {
  const index = item.id ? items.findIndex((entry) => entry.id === item.id) : -1;
  return index < 0 ? [...items, item] : items.map((entry, position) => position === index ? { ...entry, ...item } : entry);
}

function label(item: ActivityItem): string {
  if (item.type === "commandExecution") return "Command";
  if (item.type === "fileChange") return "File changes";
  if (item.type === "reasoning") return "Reasoning summary";
  return item.type.replace(/([a-z])([A-Z])/g, "$1 $2");
}

function preview(item: ActivityItem): string {
  if (item.command) return item.command;
  if (item.type === "reasoning") return item.summary?.join("\n") || (item.status === "inProgress" ? "Waiting for a reasoning summary…" : "No reasoning summary provided");
  if (item.changes) return item.changes.map((change) => change.path).join(", ");
  if (item.text) return item.text;
  return [item.server, item.tool, item.name].filter((value) => typeof value === "string").join(" · ") || "Details available when expanded";
}

export function ChatActivity({ items, working = false }: { items: ActivityItem[]; working?: boolean }) {
  if (!items.length) return null;
  return <details className="tool-activity" open={working}>
    <summary><ChevronDown size={15} /> {working ? "Working" : "Earlier activity"} · {items.length} {items.length === 1 ? "activity" : "activities"}</summary>
    <div className="activity-list">{items.map((item, index) => {
      const text = preview(item);
      const short = text.split("\n").slice(0, 2).join("\n");
      const status = (item.status || (working ? "inProgress" : "completed")).replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
      return <details className="activity-entry" key={item.id || index}>
        <summary><span className="activity-heading"><ChevronDown size={13} /><strong>{label(item)}</strong><span className={`activity-status ${status.replace(/\s/g, "-")}`}>{status}</span></span><span className={`activity-preview ${item.command ? "command-preview" : ""}`}>{short.length > 180 ? `${short.slice(0, 180)}…` : short}{text !== short && short.length <= 180 ? "…" : ""}</span></summary>
        <div className="activity-details">{item.type === "reasoning" ? item.summary?.length ? <ChatMarkdown text={item.summary.join("\n\n")} /> : <p>No reasoning summary was provided.</p> : item.command ? <><pre>{item.command}</pre>{item.cwd && <small>Working directory: {item.cwd}</small>}{item.aggregatedOutput && <pre className="activity-output">{item.aggregatedOutput}</pre>}</> : item.changes ? item.changes.map((change) => <div key={change.path}><strong>{change.path}</strong>{change.diff && <pre>{change.diff}</pre>}</div>) : item.text ? <ChatMarkdown text={item.text} /> : <pre>{JSON.stringify(item, null, 2)}</pre>}</div>
      </details>;
    })}</div>
  </details>;
}
