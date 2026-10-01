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
    api={{ request } as unknown as StudioApi} onSaved={async () => undefined}
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
