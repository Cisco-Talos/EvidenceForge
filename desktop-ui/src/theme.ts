import { useSyncExternalStore } from "react";

/** A user's appearance choice; "system" follows the macOS light/dark setting. */
export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const LIGHT_QUERY = "(prefers-color-scheme: light)";
const listeners = new Set<() => void>();
let preference: ThemePreference = "system";

function systemTheme(): ResolvedTheme {
  return typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia(LIGHT_QUERY).matches ? "light" : "dark";
}

/** The theme currently applied to the document. */
export function resolvedTheme(): ResolvedTheme {
  return preference === "system" ? systemTheme() : preference;
}

function apply(): void {
  document.documentElement.dataset.theme = resolvedTheme();
  for (const listener of listeners) listener();
}

/** Change the appearance preference and re-theme the document immediately. */
export function setThemePreference(next: ThemePreference): void {
  preference = next;
  apply();
}

/** Apply the theme and keep "system" in step with the OS appearance. Returns a disposer. */
export function startTheme(): () => void {
  apply();
  const media = typeof window.matchMedia === "function" ? window.matchMedia(LIGHT_QUERY) : null;
  const onChange = () => { if (preference === "system") apply(); };
  media?.addEventListener?.("change", onChange);
  return () => media?.removeEventListener?.("change", onChange);
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Re-render when the resolved theme changes, for assets such as theme-specific logos. */
export function useResolvedTheme(): ResolvedTheme {
  return useSyncExternalStore(subscribe, resolvedTheme, () => "dark");
}
