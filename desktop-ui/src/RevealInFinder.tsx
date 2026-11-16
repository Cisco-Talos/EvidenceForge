import { isTauri } from "@tauri-apps/api/core";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { FolderOpen } from "lucide-react";
import { CopyPathButton } from "./CopyPathButton";
import type { ObjectAction } from "./ObjectActions";

/** The platform's name for showing a file in the system file browser. */
export function revealLabel(): string {
  const platform = typeof navigator === "undefined" ? "" : navigator.userAgent;
  return /Windows/.test(platform) ? "Show in Explorer" : /Linux/.test(platform) ? "Show in file manager" : "Reveal in Finder";
}

/** Revealing needs the native shell; the browser preview cannot reach local files. */
export function canReveal(): boolean {
  return isTauri();
}

export async function revealPath(path: string): Promise<void> {
  await revealItemInDir(path);
}

/** Menu action placed beside "Copy path" in the locate group; omitted outside the native app. */
export function revealAction(path: string | null | undefined, onError: (message: string) => void, disabledReason?: string): ObjectAction[] {
  if (!canReveal() || !path) return [];
  return [{ id: "reveal", label: revealLabel(), group: "locate", disabled: !!disabledReason, reason: disabledReason, run: () => revealPath(path).catch((error) => onError(String(error))) }];
}

/** Confirmation shown after an export writes a file: where it went, with Reveal and Copy path. */
export function SavedPath({ path, onError, className = "" }: { path: string; onError: (message: string) => void; className?: string }) {
  return <div className={`path-with-copy saved-path muted small ${className}`}>
    <span className="path-value" title={path}>Saved to {path}</span>
    {canReveal() && <button type="button" className="copy-path-button" aria-label={revealLabel()} title={revealLabel()} onClick={() => void revealPath(path).catch((error) => onError(String(error)))}><FolderOpen size={14} aria-hidden="true" /></button>}
    <CopyPathButton path={path} label="Copy saved file path" onError={onError} />
  </div>;
}
