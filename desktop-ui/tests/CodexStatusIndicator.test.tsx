import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, expect, test, vi } from "vitest";
import { CodexStatusIndicator } from "../src/CodexStatusIndicator";
import type { CodexHealth, StudioApi } from "../src/api";

const native = vi.hoisted(() => ({ enabled: false, openUrl: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => native.enabled }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: native.openUrl }));

afterEach(() => { cleanup(); vi.restoreAllMocks(); native.enabled = false; native.openUrl.mockReset(); });

function setup(health: CodexHealth, activeTurns = 0) {
  const request = vi.fn(async (path: string) => {
    if (path === "/v1/codex/account/login") return { authUrl: "https://example.com/codex-login" };
    if (path === "/v1/codex/status") return { available: true, account: { account: health.availability === "ready" ? { type: "chatgpt", email: health.account_label } : null } };
    throw new Error(`Unexpected request: ${path}`);
  });
  const onReconnect = vi.fn(async () => true);
  const onError = vi.fn();
  const props = { health, activeTurns, api: { request } as unknown as StudioApi, reconnecting: false, onReconnect, onError };
  const view = render(<Tooltip.Provider><CodexStatusIndicator {...props} /></Tooltip.Provider>);
  return { request, onReconnect, onError, ...view, props };
}

test.each([
  { state: "disconnected", availability: "disconnected", detail: "Codex CLI was not found", enabled: false },
  { state: "checking", availability: "disconnected", detail: "Checking Codex connection", enabled: false },
  { state: "connected", availability: "unavailable", detail: "Log in to start work", account_label: "Signed out", enabled: true },
  { state: "stalled", availability: "unavailable", detail: "Codex did not answer account/read", enabled: true },
  { state: "connected", availability: "unavailable", detail: "No models available", account_label: "Amazon Bedrock", enabled: true },
  { state: "connected", availability: "ready", detail: "Ready for work", account_label: "author@example.com", enabled: true },
] as (CodexHealth & { enabled: boolean })[])("$availability / $detail shows details with correct Login availability", async ({ enabled, ...health }) => {
  const { request } = setup(health);
  const user = userEvent.setup();
  const indicator = screen.getByRole("button", { name: /^Codex / });
  expect(indicator.classList.contains(health.availability!)).toBe(true);
  await user.click(indicator);
  const dialog = screen.getByRole("dialog", { name: "Codex status" });
  expect(within(dialog).getByText(health.detail, { selector: "p" })).toBeTruthy();
  if (health.account_label) expect(within(dialog).getByText(health.account_label)).toBeTruthy();
  const login = within(dialog).getByRole("button", { name: "Login" });
  expect(login.hasAttribute("disabled")).toBe(!enabled);
  if (!enabled) {
    await user.click(login);
    expect(request).not.toHaveBeenCalled();
  }
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(document.activeElement).toBe(indicator);
});

test.each(["unavailable", "ready"] as const)("Login in %s state opens the shared browser sign-in flow without signing out", async (availability) => {
  const { request } = setup({ state: "connected", availability, detail: "Codex is connected", account_label: availability === "ready" ? "author@example.com" : "Signed out" });
  const open = vi.spyOn(window, "open").mockImplementation(() => null);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /^Codex / }));
  await user.click(screen.getByRole("button", { name: "Login" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/codex/account/login", "POST"));
  expect(open).toHaveBeenCalledWith("https://example.com/codex-login", "_blank", "noopener,noreferrer");
  expect(request).not.toHaveBeenCalledWith("/v1/codex/account/logout", "POST");
});

test("native Login uses the same system browser opener as Settings", async () => {
  native.enabled = true;
  setup({ state: "connected", availability: "unavailable", detail: "Signed out" });
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /^Codex / }));
  await user.click(screen.getByRole("button", { name: "Login" }));
  await waitFor(() => expect(native.openUrl).toHaveBeenCalledWith("https://example.com/codex-login"));
});

test("connected errors keep Login available and report a failed login without dismissing details", async () => {
  const { request, onError } = setup({ state: "stalled", availability: "unavailable", detail: "Request timed out" });
  request.mockImplementation(async (path) => {
    if (path === "/v1/codex/account/login") throw new Error("Login failed");
    return { available: false, error: "Request timed out" };
  });
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /^Codex / }));
  await user.click(screen.getByRole("button", { name: "Login" }));
  await waitFor(() => expect(onError).toHaveBeenCalledWith("Error: Login failed"));
  expect(screen.getByRole("dialog", { name: "Codex status" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Login" }).hasAttribute("disabled")).toBe(false);
});

test("reconnecting from green warns about active turns and stays open after failure", async () => {
  const { onReconnect, props, rerender } = setup({ state: "connected", availability: "ready", detail: "Ready for work" }, 2);
  onReconnect.mockResolvedValue(false);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /^Codex / }));
  expect(screen.getByText(/interrupt 2 active turns/)).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Reconnect" }));
  expect(onReconnect).toHaveBeenCalledOnce();
  expect(screen.getByRole("dialog", { name: "Codex status" })).toBeTruthy();
  rerender(<Tooltip.Provider><CodexStatusIndicator {...props} health={{ state: "disconnected", availability: "disconnected", detail: "Studio service connection lost" }} canReconnect={false} /></Tooltip.Provider>);
  expect(screen.getByRole("button", { name: "Reconnect" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "Login" }).hasAttribute("disabled")).toBe(true);
});
