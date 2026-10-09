import { ChevronRight } from "lucide-react";
import type { AffectedItem } from "./api";

const categories = [
  ["industry_pack", "Industry packs"],
  ["organization_pack", "Organization packs"],
  ["scenario", "Scenarios"],
] as const;

export function AffectedItems({ items }: { items: AffectedItem[] }) {
  if (!items.length) return null;
  const sorted = [...items].sort((a, b) =>
    a.name.localeCompare(b.name, undefined, { sensitivity: "base", numeric: true }) ||
    (b.version || "").localeCompare(a.version || "", undefined, { numeric: true }) ||
    (a.publisher || "").localeCompare(b.publisher || "") || a.path.localeCompare(b.path));
  return <details className="affected-items">
    <summary><ChevronRight size={13} aria-hidden="true" /> Affected items ({items.length})</summary>
    <div className="affected-items-body">{categories.map(([kind, label]) => {
      const members = sorted.filter((item) => item.kind === kind);
      return members.length ? <section key={kind} aria-label={label}>
        <h4>{label}</h4>
        <ul>{members.map((item) => <li key={item.path} title={item.path}>
          <span>{item.publisher ? `${item.publisher}/` : ""}{item.name}</span>
          {item.version && <small>{item.version}</small>}
        </li>)}</ul>
      </section> : null;
    })}</div>
  </details>;
}
