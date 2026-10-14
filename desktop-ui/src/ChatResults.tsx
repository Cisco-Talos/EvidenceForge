import { useId } from "react";
import { FileText } from "lucide-react";
import type { TimelineResult } from "./chatTimeline";

type Operation = NonNullable<TimelineResult["operation"]>;
const groups: { operation: Operation; label: string }[] = [
  { operation: "edited", label: "Edited files" },
  { operation: "created", label: "Created files" },
  { operation: "renamed", label: "Renamed or moved files" },
  { operation: "removed", label: "Removed files" },
  { operation: "changed", label: "Other file changes" },
];
function operationFor(result: TimelineResult): Operation {
  if (result.operation) return result.operation;
  if (["add", "created"].includes(result.kind || "")) return "created";
  if (["delete", "deleted", "removed"].includes(result.kind || "")) return "removed";
  if (["rename", "renamed", "move", "moved"].includes(result.kind || "")) return "renamed";
  return !result.kind || ["update", "modified", "edited"].includes(result.kind) ? "edited" : "changed";
}
function quantity(value: number, singular: string): string {
  return `${value.toLocaleString()} ${singular}${value === 1 ? "" : "s"}`;
}
function currentSize(result: TimelineResult): string | null {
  const parts: string[] = [];
  if (result.current_lines != null) parts.push(quantity(result.current_lines, "line"));
  if (result.current_characters != null) parts.push(quantity(result.current_characters, "character"));
  if (!parts.length && result.current_bytes != null) parts.push(quantity(result.current_bytes, "byte"));
  return parts.length ? `Current size: ${parts.join(" · ")}` : null;
}

export function ChatResults({ results }: { results: TimelineResult[] }) {
  const identity = useId();
  return <section className="chat-results" aria-label="Files affected">
    {groups.map(({ operation, label }) => {
      const entries = results.filter((result) => operationFor(result) === operation);
      if (!entries.length) return null;
      return <section className={`chat-result-group ${operation}`} aria-labelledby={`${identity}-${operation}`} key={operation}>
        <h3 id={`${identity}-${operation}`}>{label}{" "}<span className="chat-result-count">{entries.length}</span></h3>
        <ul>{entries.map((result) => {
          const path = result.relative_path || result.path.split(/[\\/]/).pop() || result.path;
          const available = operation !== "removed" && result.available !== false;
          const size = currentSize(result);
          const hasCounts = result.lines_added != null && result.lines_removed != null;
          return <li className="chat-result-row" key={result.id}>
            <FileText className="chat-result-icon" size={17} aria-hidden="true" />
            <div className="chat-result-info">
              <span className="chat-result-path" title={result.path}>{path}</span>
              {result.previous_relative_path && <small className="chat-result-previous" title={result.previous_path || undefined}>Moved from {result.previous_relative_path}</small>}
              {operation !== "created" && hasCounts && <small className="chat-result-diff-stats">{!!result.lines_added && <span className="lines-added">+{quantity(result.lines_added, "line")}</span>}{!!result.lines_removed && <span className="lines-removed">−{quantity(result.lines_removed, "line")}</span>}{result.lines_added === 0 && result.lines_removed === 0 && <span>0 lines added or removed</span>}</small>}
              {result.metadata_only && <small>File permissions changed</small>}
              {operation === "edited" && !hasCounts && !result.metadata_only && <small>Recorded line counts unavailable</small>}
              {size && <small>{size}</small>}
              {!available && operation !== "removed" && <small>Source file is no longer available</small>}
            </div>
          </li>;
        })}</ul>
      </section>;
    })}
  </section>;
}
