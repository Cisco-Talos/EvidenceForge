import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { MissingScenarioSource } from "../src/MissingScenarioSource";
import { belongsToScenario } from "../src/scenarioSources";
import type { CatalogItem, Conversation, StudioApi, StudioJob, StudioSnapshot } from "../src/api";

vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => false, invoke: vi.fn() }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });
const item = { id: "missing", name: "test", path: "/workspace/old/scenario.yaml" } as CatalogItem;
function fixture(request = vi.fn(async () => ({ ...item, path: "/workspace/recovered/scenario.yaml" })), active = false) {
  const onRecovered = vi.fn(async () => undefined);
  const onRemoved = vi.fn(async () => undefined);
  const conversations = [{ id: "chat", active }] as Conversation[];
  render(<MissingScenarioSource item={item} conversations={conversations} jobs={[]} api={{ request } as unknown as StudioApi} onRecovered={onRecovered} onRemoved={onRemoved} onRuns={vi.fn()} />);
  return { request, onRecovered, onRemoved, user: userEvent.setup() };
}

test("missing entry opens a recovery page and locates a selected source", async () => {
  const { user, request, onRecovered } = fixture();
  expect(screen.getByRole("heading", { name: "test" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Locate source" })).toBeDisabled();
  await user.type(screen.getByRole("textbox", { name: "Scenario YAML path" }), "/workspace/recovered/scenario.yaml");
  await user.click(screen.getByRole("button", { name: "Locate source" }));
  expect(request).toHaveBeenCalledWith("/v1/scenarios/missing/source", "POST", { path: "/workspace/recovered/scenario.yaml" });
  expect(onRecovered).toHaveBeenCalledWith({ ...item, path: "/workspace/recovered/scenario.yaml" });
});

test("removing a registration requires the explicit removal action", async () => {
  const { user, request, onRemoved } = fixture();
  await user.click(screen.getByRole("button", { name: "Remove library entry…" }));
  expect(request).not.toHaveBeenCalled();
  expect(screen.getByText(/Saved conversations will no longer appear/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(request).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Remove library entry…" }));
  await user.click(screen.getByRole("button", { name: "Remove entry" }));
  expect(request).toHaveBeenCalledWith("/v1/scenarios/missing/registration", "DELETE");
  expect(onRemoved).toHaveBeenCalled();
});

test("recovery error is shown and an active chat prevents changes", async () => {
  const request = vi.fn(async () => { throw new Error("Different identity"); });
  const { user } = fixture(request);
  await user.type(screen.getByRole("textbox", { name: "Scenario YAML path" }), "/workspace/other.yaml");
  await user.click(screen.getByRole("button", { name: "Locate source" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Different identity");
  cleanup();
  fixture(undefined, true);
  expect(screen.getByRole("button", { name: "Locate source" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Remove library entry…" })).toBeDisabled();
});

test("retained runs remain associated with previous source paths", () => {
  const snapshot = { source_paths: { missing: [item.path, "/workspace/earlier/scenario.yaml"] } } as unknown as StudioSnapshot;
  expect(belongsToScenario({ kind: "generation", scenario: "/workspace/earlier/scenario.yaml" } as StudioJob, item, snapshot)).toBe(true);
  expect(belongsToScenario({ kind: "generation", scenario: "/workspace/unrelated.yaml" } as StudioJob, item, snapshot)).toBe(false);
});
