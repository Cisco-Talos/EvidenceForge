import type { DependencyRow } from "./api";

export function packSelection(rows: DependencyRow[], choices: Set<string>) {
  const byKey = new Map(rows.filter((row) => row.kind === "pack").map((row) => [row.key, row]));
  const selected = new Set([...choices].filter((key) => byKey.has(key)));
  const requiredBy = new Map<string, string[]>();
  const pending = [...selected];
  while (pending.length) {
    const key = pending.pop()!;
    for (const dependency of byKey.get(key)?.dependencies || []) {
      requiredBy.set(dependency, [...(requiredBy.get(dependency) || []), key]);
      if (!selected.has(dependency)) { selected.add(dependency); pending.push(dependency); }
    }
  }
  const blocked = !selected.size || [...selected].some((key) => {
    const row = byKey.get(key);
    return !row || row.status === "conflict" || row.status === "missing";
  });
  return { selected, requiredBy, blocked };
}
