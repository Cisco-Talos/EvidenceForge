import { namingRules } from "./generated/naming";

export function artifactNameError(name: string, kind: "scenario" | "pack"): string | null {
  if (!name) return `Enter a ${kind} name.`;
  const rule = namingRules[kind];
  return new RegExp(rule.pattern).exec(name)?.[0] === name ? null : rule.message;
}

export function suggestedIdentifier(displayName: string): string {
  return displayName.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

/** Titles never participate in artifact identity or filesystem naming. */
export function artifactTitle(item: { name: string; display_name?: string | null }): string {
  return item.display_name || item.name;
}

export function draftTitle(draft: { title: string; draft_name?: string | null; draft_display_name?: string | null }): string {
  return draft.draft_display_name || draft.draft_name || draft.title;
}

/** A bounded Save-dialog suggestion; sources and receipts retain the full identifier. */
export function artifactFilename(item: { name: string; version?: string }, extension: string): string {
  const stem = item.name.replace(/[^A-Za-z0-9_-]+/g, "-").slice(0, 160) || "artifact";
  return `${stem}${item.version ? `-${item.version}` : ""}.${extension}`;
}
