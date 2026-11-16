import { useSyncExternalStore } from "react";

/** A user's appearance choice; "system" follows the macOS light/dark setting. */
export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const LIGHT_QUERY = "(prefers-color-scheme: light)";
/**
 * Appearance is a per-Mac view preference kept in the app's own web storage, shared by every
 * Studio window. It is deliberately not part of the versioned service settings, which would need
 * a state migration for a purely cosmetic choice.
 */
export const THEME_STORAGE_KEY = "evidenceforge.appearance";
const listeners = new Set<() => void>();
let preference: ThemePreference = "system";

function storedPreference(): ThemePreference {
  try {
    const value = window.localStorage?.getItem(THEME_STORAGE_KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch { return "system"; }
}

/** The saved appearance choice. */
export function themePreference(): ThemePreference {
  return preference;
}

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

/** Change and remember the appearance preference, re-theming the document immediately. */
export function setThemePreference(next: ThemePreference): void {
  preference = next;
  try {
    if (next === "system") window.localStorage?.removeItem(THEME_STORAGE_KEY);
    else window.localStorage?.setItem(THEME_STORAGE_KEY, next);
  } catch { /* Storage can be unavailable; the choice still applies to this window. */ }
  apply();
}

/** Apply the theme and keep "system" in step with the OS appearance. Returns a disposer. */
export function startTheme(): () => void {
  preference = storedPreference();
  apply();
  const media = typeof window.matchMedia === "function" ? window.matchMedia(LIGHT_QUERY) : null;
  const onChange = () => { if (preference === "system") apply(); };
  // Another Studio window (such as About) changed the choice.
  const onStorage = (event: StorageEvent) => { if (event.key === THEME_STORAGE_KEY || event.key === null) { preference = storedPreference(); apply(); } };
  media?.addEventListener?.("change", onChange);
  window.addEventListener("storage", onStorage);
  return () => { media?.removeEventListener?.("change", onChange); window.removeEventListener("storage", onStorage); };
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Re-render when the appearance preference changes, for the Settings control. */
export function useThemePreference(): ThemePreference {
  return useSyncExternalStore(subscribe, themePreference, () => "system");
}

/** Re-render when the resolved theme changes, for assets such as theme-specific logos. */
export function useResolvedTheme(): ResolvedTheme {
  return useSyncExternalStore(subscribe, resolvedTheme, () => "dark");
}
