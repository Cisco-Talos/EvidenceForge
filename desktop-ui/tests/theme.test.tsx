import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import { StudioBrand } from "../src/StudioBrand";
import { setThemePreference, startTheme, THEME_STORAGE_KEY, themePreference } from "../src/theme";

type Listener = () => void;

function mockSystemAppearance(light: boolean) {
  const listeners = new Set<Listener>();
  const media = {
    get matches() { return light; },
    addEventListener: (_: string, listener: Listener) => listeners.add(listener),
    removeEventListener: (_: string, listener: Listener) => listeners.delete(listener),
  };
  vi.stubGlobal("matchMedia", vi.fn(() => media));
  return { change(next: boolean) { light = next; listeners.forEach((listener) => listener()); } };
}

afterEach(() => {
  cleanup();
  setThemePreference("system");
  vi.unstubAllGlobals();
  delete document.documentElement.dataset.theme;
  window.localStorage.removeItem(THEME_STORAGE_KEY);
});

test("startTheme follows the system appearance until a preference overrides it", () => {
  const system = mockSystemAppearance(true);
  const stop = startTheme();
  expect(document.documentElement.dataset.theme).toBe("light");
  act(() => system.change(false));
  expect(document.documentElement.dataset.theme).toBe("dark");
  setThemePreference("light");
  act(() => system.change(false));
  expect(document.documentElement.dataset.theme).toBe("light");
  stop();
});

test("startTheme defaults to dark when the system appearance is unavailable", () => {
  vi.stubGlobal("matchMedia", undefined);
  startTheme()();
  expect(document.documentElement.dataset.theme).toBe("dark");
});

test("full brand logo switches artwork with the theme and the sidebar brand stays compact", () => {
  mockSystemAppearance(false);
  startTheme();
  const view = render(<StudioBrand className="brand about-brand" />);
  expect(screen.getByAltText("EvidenceForge")).toHaveAttribute("src", "/brand/evidenceforge-dark.png");
  act(() => setThemePreference("light"));
  expect(screen.getByAltText("EvidenceForge")).toHaveAttribute("src", "/brand/evidenceforge-light.png");
  view.rerender(<StudioBrand compact />);
  expect(screen.queryByAltText("EvidenceForge")).not.toBeInTheDocument();
  expect(screen.getByText("EvidenceForge")).toBeInTheDocument();
  expect(screen.getByText("Studio")).toBeInTheDocument();
});

test("an explicit appearance persists, restores on launch and follows other Studio windows", () => {
  mockSystemAppearance(false);
  setThemePreference("light");
  expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
  setThemePreference("system");
  expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
  window.localStorage.setItem(THEME_STORAGE_KEY, "light");
  const stop = startTheme();
  expect(themePreference()).toBe("light");
  expect(document.documentElement.dataset.theme).toBe("light");
  window.localStorage.setItem(THEME_STORAGE_KEY, "dark");
  act(() => { window.dispatchEvent(new StorageEvent("storage", { key: THEME_STORAGE_KEY })); });
  expect(document.documentElement.dataset.theme).toBe("dark");
  stop();
});
