import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { SettingsView } from "../src/SettingsView";
import type { StudioApi, StudioSettings } from "../src/api";
import { Tooltip } from "radix-ui";

vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => false }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openPath: vi.fn(), openUrl: vi.fn() }));

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

test("Codex sign-in shows pending state and discovers the completed account", async () => {
  const settings = {
    workspace: "/tmp/EvidenceForge", recent_workspaces: [], output_parents: {},
    max_concurrent_generations: 2, checkpoint_hours: 24,
    quit: {
      action: "continue", continue_queued_generations: true, continue_evaluations: "continue",
      pause_close_timing: "handoff", pause_evaluations: "finish",
      kill_incomplete_bundles: "preserve", authoring_turns: "stop",
    },
    skill_install_scope: "global", skill_install_agent: "all",
    codex_path: null, eforge_path: null,
  } as StudioSettings;
  let statusReads = 0;
  const request = vi.fn(async (path: string) => {
    if (path === "/v1/codex/status") {
      statusReads += 1;
      return {
        available: true,
        account: { account: statusReads < 3 ? null : { type: "chatgpt", email: "author@example.com" } },
      };
    }
    if (path === "/v1/codex/account/login") return { authUrl: "https://example.com/login" };
    throw new Error(`Unexpected request: ${path}`);
  });
  const open = vi.spyOn(window, "open").mockImplementation(() => null);
  render(<Tooltip.Provider><SettingsView
    settings={settings} paths={{ data: "/tmp/data", logs: "/tmp/logs" }}
    api={{ request, libraryPreferences: async () => ({ remember_view: true }) } as unknown as StudioApi} onSaved={async () => undefined}
    onError={vi.fn()}
  /></Tooltip.Provider>);
  await userEvent.setup().click(screen.getByRole("button", { name: "Authoring & tools" }));
  await screen.findByText("Signed out");
  await userEvent.setup().click(screen.getByRole("button", { name: "Sign in" }));
  expect(open).toHaveBeenCalledWith("https://example.com/login", "_blank", "noopener,noreferrer");
  expect(await screen.findByText("Waiting for sign-in…")).toBeTruthy();
  await waitFor(() => expect(screen.getByText("author@example.com")).toBeTruthy(), { timeout: 5000 });
  expect(screen.getByRole("button", { name: "Sign out" }).hasAttribute("disabled")).toBe(false);
});

test("search excerpt count defaults to five and is saved as a preference", async () => {
  const settings = {
    workspace: "/tmp/EvidenceForge", recent_workspaces: [], output_parents: {},
    max_concurrent_generations: 2, checkpoint_hours: 24, search_match_limit: 5,
    quit: { action: "continue", continue_queued_generations: true, continue_evaluations: "continue", pause_close_timing: "handoff", pause_evaluations: "finish", kill_incomplete_bundles: "preserve", authoring_turns: "stop" },
    skill_install_scope: "global", skill_install_agent: "all", codex_path: null, eforge_path: null,
  } as StudioSettings;
  const request = vi.fn(async (path: string, _method?: string, body?: unknown) => {
    if (path === "/v1/settings") return body;
    if (path === "/v1/codex/status") return { available: false };
    return {};
  });
  render(<Tooltip.Provider><SettingsView settings={settings} paths={{ data: "/tmp/data", logs: "/tmp/logs" }} api={{ request, libraryPreferences: async () => ({ remember_view: true }) } as unknown as StudioApi} onSaved={async () => undefined} onError={vi.fn()} /></Tooltip.Provider>);
  const user = userEvent.setup();
  const input = screen.getByRole("spinbutton", { name: "Search matches per item" });
  expect((input as HTMLInputElement).value).toBe("5");
  await waitFor(() => expect(screen.getByRole("button", { name: "Save settings" }).hasAttribute("disabled")).toBe(true));
  await user.clear(input);
  await user.type(input, "8");
  await user.click(screen.getByRole("button", { name: "Save settings" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/settings", "PUT", expect.objectContaining({ search_match_limit: 8 })));
  await waitFor(() => expect(screen.getByRole("button", { name: "Save settings" }).hasAttribute("disabled")).toBe(true));
});
