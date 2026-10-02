import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, expect, test, vi } from "vitest";
import { EnvironmentView } from "../src/EnvironmentView";
import type { CatalogItem, EnvironmentReport, StudioApi } from "../src/api";

const item = { id: "scenario", source_sha256: "source", name: "Example" } as CatalogItem;
const report: EnvironmentReport = {
  source_sha256: "source", project_root: "/workspace", valid: true, error: "", compiled_sha256: "compiled", authored_kind: "scenario-2.0",
  selected_packs: [{ source: "project", publisher: "team", type: "organization", name: "office", version: "2.0.0", digest: "d".repeat(64), location: "/workspace/office" }, { source: "package", publisher: "evidenceforge", type: "industry", name: "healthcare", version: "1.0.0", digest: "a".repeat(64), location: "/package" }],
  effective_scenario: { environment: { users: [{ name: "alice" }] } }, field_origins: { description: "sources/brief.yaml" }, organization_model_origins: { "network.segments": "office/pack.yaml" }, catalog_origins: {}, catalog_field_origins: { "personas.analyst": "healthcare/pack.yaml" }, merge_decisions: [{ path: "users", action: "replace", lower_layer: "organization", higher_layer: "scenario", winner: "scenario" }],
  overlay_root: "/workspace/.eforge/config", overlay_files: [{ path: "activity/dns_registry.yaml", size: 20 }], overlays_truncated: false,
};
const packs = [
  { kind: "organization_pack", name: "office", version: "2.0.0", publisher: "team", publisher_display_name: "Training Team", pack_source: "workspace" },
  { kind: "organization_pack", name: "office", version: "3.0.0", publisher: "team", publisher_display_name: "Training Team", pack_source: "workspace" },
  { kind: "industry_pack", name: "healthcare", version: "1.0.0", publisher: "evidenceforge", publisher_display_name: "EvidenceForge", pack_source: "bundled" },
] as CatalogItem[];
function setup(request = vi.fn(async () => report), onPrepare = vi.fn(async (_prompt: string) => undefined)) {
  const api = { request, readTextPreview: vi.fn(async () => ({ text: "domains: []", truncated: false, binary: false })), download: vi.fn(async () => ({ status: "browser" })) } as unknown as StudioApi;
  const onError = vi.fn();
  const props = { item, packs, api, onPrepare, onError, dependencyFingerprint: "deps-1" };
  const view = render(<Tooltip.Provider><EnvironmentView {...props} /></Tooltip.Provider>);
  return { ...view, api, onPrepare, onError, props };
}
afterEach(() => cleanup());

test("exact versions and source declarations are searchable and refresh after dependency changes", async () => {
  const { api, props, rerender } = setup();
  expect(await screen.findByText("project:team:organization:office@2.0.0")).toBeVisible();
  const user = userEvent.setup();
  await user.type(screen.getByRole("textbox", { name: "Search environment origins" }), "brief.yaml");
  expect(screen.getByText("sources/brief.yaml")).toBeVisible();
  expect(screen.queryByText("office/pack.yaml")).not.toBeInTheDocument();
  rerender(<Tooltip.Provider><EnvironmentView {...props} dependencyFingerprint="deps-2" /></Tooltip.Provider>);
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.getByRole("button", { name: "Refresh environment" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Refresh environment" }));
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(3));
});

test("an exact organization choice prepares a reviewable request with locked dependencies", async () => {
  const { onPrepare } = setup();
  await screen.findByText("Selected packs");
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Choose packs" }));
  const dialog = screen.getByRole("dialog", { name: "Choose environment packs" });
  expect(within(dialog).getByRole("radio", { name: "One organization" })).toBeChecked();
  await user.type(within(dialog).getByRole("textbox", { name: "Search environment packs" }), "3.0.0");
  await user.click(within(dialog).getByRole("radio", { name: /office 3.0.0/ }));
  await user.click(within(dialog).getByRole("button", { name: "Prepare in chat" }));
  await waitFor(() => expect(onPrepare).toHaveBeenCalledOnce());
  const prompt = onPrepare.mock.calls[0][0];
  expect(prompt).toContain("project:team:organization:office@3.0.0");
  expect(prompt).toContain("locked industry dependencies");
  expect(prompt).toContain("nested includes");
  expect(prompt).not.toContain("@2.0.0");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

test("empty industry choices are gated and failed preparation retains the selection", async () => {
  const onPrepare = vi.fn(async (_prompt: string) => { throw new Error("Could not create conversation"); });
  const { onError } = setup(undefined, onPrepare);
  await screen.findByText("Selected packs");
  const user = userEvent.setup();
  const trigger = screen.getByRole("button", { name: "Choose packs" });
  await user.click(trigger);
  const dialog = screen.getByRole("dialog");
  await user.click(within(dialog).getByRole("radio", { name: "Industry packs" }));
  const industry = within(dialog).getByRole("checkbox", { name: /healthcare/ });
  expect(industry).not.toBeChecked();
  expect(within(dialog).getByRole("button", { name: "Prepare in chat" })).toBeDisabled();
  await user.click(industry);
  await user.click(industry);
  expect(within(dialog).getByRole("button", { name: "Prepare in chat" })).toBeDisabled();
  await user.click(industry);
  await user.click(within(dialog).getByRole("button", { name: "Prepare in chat" }));
  await waitFor(() => expect(onError).toHaveBeenCalledWith("Error: Could not create conversation"));
  expect(dialog).toBeVisible();
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(trigger).toHaveFocus();
});

test("overlays use the contained file viewer and authenticated export route", async () => {
  const { api } = setup();
  await screen.findByText("Selected packs");
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "activity/dns_registry.yaml" }));
  const viewer = screen.getByRole("dialog", { name: "Workspace overlay" });
  await waitFor(() => expect(api.readTextPreview).toHaveBeenCalledWith("/v1/environment/scenario/files/activity/dns_registry.yaml"));
  expect(await within(viewer).findByLabelText("Preview of activity/dns_registry.yaml")).toHaveTextContent("domains: []");
  await user.click(within(viewer).getByRole("button", { name: "Download file" }));
  expect(api.download).toHaveBeenCalledWith("/v1/environment/scenario/files/activity/dns_registry.yaml", "dns_registry.yaml", expect.any(Function));
});

test("an old response cannot replace a newly selected scenario", async () => {
  let resolveOld!: (report: EnvironmentReport) => void;
  const old = new Promise<EnvironmentReport>((resolve) => { resolveOld = resolve; });
  const request = vi.fn().mockReturnValueOnce(old).mockResolvedValueOnce({ ...report, selected_packs: [], source_sha256: "next" });
  const { props, rerender } = setup(request);
  rerender(<Tooltip.Provider><EnvironmentView {...props} item={{ ...item, id: "next", source_sha256: "next" }} /></Tooltip.Provider>);
  expect(await screen.findByText(/inline environment and defaults/)).toBeVisible();
  await act(async () => resolveOld(report));
  expect(screen.queryByText("project:team:organization:office@2.0.0")).not.toBeInTheDocument();
});
