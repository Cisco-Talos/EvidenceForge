import { Pencil, RotateCcw } from "lucide-react";

export function valueAt(value: unknown, parts: string[]): unknown {
  return parts.reduce<unknown>((node, part) => node && typeof node === "object" ? (node as Record<string, unknown>)[part] : undefined, value);
}

export function sameValue(first: unknown, second: unknown): boolean {
  if (first === second) return true;
  if (!first || !second || typeof first !== "object" || typeof second !== "object") return false;
  if (Array.isArray(first) !== Array.isArray(second)) return false;
  const a = Object.entries(first), b = Object.entries(second);
  return a.length === b.length && a.every(([key, value]) => Object.prototype.hasOwnProperty.call(second, key) && sameValue(value, (second as Record<string, unknown>)[key]));
}

export function includesPath(paths: string[] | undefined, path: string): boolean {
  return !!paths?.some((entry) => entry === "*" || entry === path || entry.startsWith(path + ".") || path.startsWith(entry + "."));
}

export function restoreValue(value: Record<string, unknown>, inherited: Record<string, unknown>, path: string): Record<string, unknown> {
  const next = structuredClone(value);
  const parts = path.split(".");
  let node = next;
  for (const part of parts.slice(0, -1)) { if (!node[part] || typeof node[part] !== "object") node[part] = {}; node = node[part] as Record<string, unknown>; }
  const original = valueAt(inherited, parts);
  if (original === undefined) delete node[parts[parts.length - 1]]; else node[parts[parts.length - 1]] = structuredClone(original);
  return next;
}

export function retainRestorations(paths: string[], value: Record<string, unknown>, inherited: Record<string, unknown>): string[] {
  const retained: string[] = [];
  function visit(path: string, current: unknown, original: unknown) {
    if (sameValue(current, original)) { retained.push(path); return; }
    if (current && original && typeof current === "object" && typeof original === "object" && !Array.isArray(current) && !Array.isArray(original)) {
      for (const key of new Set([...Object.keys(current), ...Object.keys(original)])) visit(path ? `${path}.${key}` : key, valueAt(current, [key]), valueAt(original, [key]));
    }
  }
  for (const path of paths) {
    if (path === "*") visit("", value, inherited);
    else visit(path, valueAt(value, path.split(".")), valueAt(inherited, path.split(".")));
  }
  return retained.map((path) => path || "*");
}

export function OverrideMark({ restoring = false }: { restoring?: boolean }) {
  return <span className={`asset-override-mark ${restoring ? "restoring" : ""}`} title={restoring ? "This scenario override will be removed when you save." : "Customized in this scenario."}>{restoring ? <RotateCcw size={12} /> : <Pencil size={12} />}{restoring ? "Restoring" : "Customized"}</span>;
}
