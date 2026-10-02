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
  declarations: [{ path: "description", layer: "Scenario", source: "brief.yaml", source_key: "sources/brief.yaml", source_size: 70, line: 5, value: "Clinic exercise", value_found: true }, { path: "environment.network.segments", layer: "Organization", source: "office/pack.yaml", source_key: "packs/office/pack.yaml", value: [], value_found: true }, { path: "persona_catalog.analyst", layer: "Pack catalog", source: "healthcare/pack.yaml", source_key: "packs/healthcare/pack.yaml", value: false, value_found: true }],
  configuration: { context_path: null, cli_command: "eforge generate /workspace/scenario.yaml --project-root /workspace", scopes: [{ id: "workspace", name: "Workspace", root: "/workspace/.eforge/config", enabled: true, files: [{ path: "activity/dns_registry.yaml", size: 20 }] }, { id: "scenario", name: "Scenario", root: "/workspace/scenario-config", enabled: false, files: [] }] },
  overlay_root: "/workspace/.eforge/config", overlay_files: [{ path: "activity/dns_registry.yaml", size: 20 }], overlays_truncated: false,
};
const packs = [
  { kind: "organization_pack", name: "office", version: "2.0.0", publisher: "team", publisher_display_name: "Training Team", pack_source: "workspace" },
  { kind: "organization_pack", name: "office", version: "3.0.0", publisher: "team", publisher_display_name: "Training Team", pack_source: "workspace" },
  { kind: "industry_pack", name: "healthcare", version: "1.0.0", publisher: "evidenceforge", publisher_display_name: "EvidenceForge", pack_source: "bundled" },
] as CatalogItem[];
function setup(request = vi.fn(async () => report), onPrepare = vi.fn(async (_prompt: string) => undefined)) {
  const api = { request, readTextPreview: vi.fn(async () => ({ text: "# Header\n# Context\n\ndomains: []\ndescription: Clinic exercise\n", truncated: false, binary: false })), download: vi.fn(async () => ({ status: "browser" })) } as unknown as StudioApi;
  const onError = vi.fn();
  const props = { item, packs, api, onPrepare, onError, dependencyFingerprint: "deps-1" };
  const view = render(<Tooltip.Provider><EnvironmentView {...props} /></Tooltip.Provider>);
  return { ...view, api, onPrepare, onError, props };
}
afterEach(() => cleanup());

test("exact versions and source declarations are searchable and refresh after dependency changes", async () => {
  const { api, props, rerender } = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Selected packs 2 packs" }));
  expect(screen.getByText("project:team:organization:office@2.0.0")).toBeVisible();
  expect(screen.queryByRole("textbox", { name: "Search environment origins" })).not.toBeInTheDocument();
  await user.click(screen.getByText("Source declarations"));
  await user.type(screen.getByRole("textbox", { name: "Search environment origins" }), "brief.yaml");
  expect(screen.getByText("brief.yaml:5")).toBeVisible();
  expect(screen.getByText("Clinic exercise")).toBeVisible();
  expect(screen.queryByText("office/pack.yaml")).not.toBeInTheDocument();
  rerender(<Tooltip.Provider><EnvironmentView {...props} dependencyFingerprint="deps-2" /></Tooltip.Provider>);
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.getByRole("button", { name: "Refresh environment" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Refresh environment" }));
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(3));
});

test("declaring YAML opens from a field by keyboard with its inspected revision", async () => {
  const { api } = setup();
  await screen.findByText("Source declarations");
  const user = userEvent.setup();
  await user.click(screen.getByText("Source declarations"));
  const field = screen.getByRole("button", { name: "View declaring YAML for description" });
  field.focus();
  await user.keyboard("{Enter}");
  const viewer = screen.getByRole("dialog", { name: "Declaring YAML" });
  await waitFor(() => expect(api.readTextPreview).toHaveBeenCalledWith("/v1/environment/scenario/declarations/files/compiled/sources/brief.yaml", 256 * 1024));
  expect(await within(viewer).findByLabelText("Preview of compiled/sources/brief.yaml")).toHaveTextContent("domains: []");
  expect(within(viewer).getByLabelText("Matched declaration, line 5")).toHaveTextContent("description: Clinic exercise");
  expect(within(viewer).queryByRole("button", { name: "Copy file path" })).not.toBeInTheDocument();
  await user.click(within(viewer).getByRole("button", { name: "Download file" }));
  expect(api.download).toHaveBeenCalledWith("/v1/environment/scenario/declarations/files/compiled/sources/brief.yaml", "brief.yaml", expect.any(Function));
});

test("declarations page through bounded rows and search values without hiding false or empty values", async () => {
  const declarations = Array.from({ length: 23 }, (_, index) => ({ path: `field.${index}`, layer: "Scenario" as const, source: "scenario.yaml", source_key: "sources/scenario.yaml", value: index === 0 ? false : index === 1 ? 0 : index === 2 ? "" : index === 3 ? null : `value-${index}`, value_found: true }));
  setup(vi.fn(async () => ({ ...report, declarations })));
  await screen.findByText("Source declarations");
  const user = userEvent.setup();
  await user.click(screen.getByText("Source declarations"));
  expect(screen.getAllByRole("row")).toHaveLength(11);
  for (const value of ["false", "0", '""', "null"]) expect(screen.getByText(value, { exact: true })).toBeVisible();
  expect(screen.getByText("1–10 of 23 fields")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Next declarations" }));
  expect(screen.getByText("11–20 of 23 fields")).toBeVisible();
  await user.type(screen.getByRole("textbox", { name: "Search environment origins" }), "value-22");
  expect(screen.getByText("1–1 of 1 fields")).toBeVisible();
  expect(screen.getByText("field.22")).toBeVisible();
  expect(screen.getByRole("button", { name: "Next declarations" })).toBeDisabled();
  await user.click(screen.getByText("value-22"));
  expect(screen.getByRole("dialog", { name: "Declaring YAML" })).toBeVisible();
});

test("long declared values expand safely without opening the source viewer", async () => {
  const value = "<script>display text only</script> " + "extended context ".repeat(12);
  setup(vi.fn(async () => ({ ...report, declarations: [{ ...report.declarations[0], value }] })));
  await screen.findByText("Source declarations");
  const user = userEvent.setup();
  await user.click(screen.getByText("Source declarations"));
  await user.click(screen.getByText(/<script>display text only<\/script>.*…/));
  expect(screen.getByText(value.trim(), { selector: "pre" })).toBeVisible();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(document.querySelector("script")).toBeNull();
});

test("an exact organization choice prepares a reviewable request with locked dependencies", async () => {
  const { onPrepare } = setup();
  await screen.findByRole("button", { name: "Selected packs 2 packs" });
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
  await screen.findByRole("button", { name: "Selected packs 2 packs" });
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
  await screen.findByRole("button", { name: "Selected packs 2 packs" });
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Configuration layers 1 enabled · 2 layers" }));
  await user.click(screen.getByText("View configuration files"));
  await user.click(screen.getByRole("button", { name: "activity/dns_registry.yaml" }));
  const viewer = screen.getByRole("dialog", { name: "Configuration overlay" });
  await waitFor(() => expect(api.readTextPreview).toHaveBeenCalledWith("/v1/environment/scenario/layers/workspace/files/activity/dns_registry.yaml"));
  expect(await within(viewer).findByLabelText("Preview of activity/dns_registry.yaml")).toHaveTextContent("domains: []");
  await user.click(within(viewer).getByRole("button", { name: "Download file" }));
  expect(api.download).toHaveBeenCalledWith("/v1/environment/scenario/layers/workspace/files/activity/dns_registry.yaml", "dns_registry.yaml", expect.any(Function));
});

test("an old response cannot replace a newly selected scenario", async () => {
  let resolveOld!: (report: EnvironmentReport) => void;
  const old = new Promise<EnvironmentReport>((resolve) => { resolveOld = resolve; });
  const request = vi.fn().mockReturnValueOnce(old).mockResolvedValueOnce({ ...report, selected_packs: [], source_sha256: "next" });
  const { props, rerender } = setup(request);
  rerender(<Tooltip.Provider><EnvironmentView {...props} item={{ ...item, id: "next", source_sha256: "next" }} /></Tooltip.Provider>);
  await userEvent.setup().click(await screen.findByRole("button", { name: "Selected packs 0 packs" }));
  expect(screen.getByText(/inline environment and defaults/)).toBeVisible();
  await act(async () => resolveOld(report));
  expect(screen.queryByText("project:team:organization:office@2.0.0")).not.toBeInTheDocument();
});


test("scenario configuration can be toggled and is refreshed before inspection", async () => {
  const { api } = setup();
  await userEvent.setup().click(await screen.findByRole("button", { name: "Configuration layers 1 enabled · 2 layers" }));
  const checkbox = screen.getByRole("checkbox", { name: "Use Scenario configuration" });
  expect(checkbox).not.toBeChecked();
  await userEvent.setup().click(checkbox);
  await waitFor(() => expect(api.request).toHaveBeenCalledWith("/v1/scenarios/scenario/configuration", "POST", { scenario_enabled: true }));
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(3));
});


test("inspection sections start folded, expose counts, and expand independently by keyboard", async () => {
  setup();
  const packs = await screen.findByRole("button", { name: "Selected packs 2 packs" });
  const layers = screen.getByRole("button", { name: "Configuration layers 1 enabled · 2 layers" });
  const overrides = screen.getByRole("button", { name: "Overrides and precedence 1 override" });
  for (const toggle of [packs, layers, overrides]) expect(toggle).toHaveAttribute("aria-expanded", "false");
  expect(screen.queryByText("project:team:organization:office@2.0.0")).not.toBeInTheDocument();
  expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  expect(screen.queryByText("organization → scenario")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Choose packs" })).toBeVisible();
  overrides.focus();
  await userEvent.setup().keyboard("{Enter}");
  expect(overrides).toHaveAttribute("aria-expanded", "true");
  expect(screen.getByText("organization → scenario")).toBeVisible();
  expect(layers).toHaveAttribute("aria-expanded", "false");
});

test("source pages provide first, last, numbered jumps and accessible current-page state", async () => {
  const declarations = Array.from({ length: 120 }, (_, index) => ({ ...report.declarations[0], path: `field.${index}`, value: `value-${index}` }));
  setup(vi.fn(async () => ({ ...report, declarations })));
  const user = userEvent.setup();
  await user.click(await screen.findByText("Source declarations"));
  const pages = screen.getByRole("navigation", { name: "Source declaration pages" });
  expect(within(pages).getByRole("button", { name: "First declarations page" })).toBeDisabled();
  expect(within(pages).getByRole("button", { name: "Declarations page 1" })).toHaveAttribute("aria-current", "page");
  expect(within(pages).getByText("…")).toBeVisible();
  await user.click(within(pages).getByRole("button", { name: "Last declarations page" }));
  expect(screen.getByText("111–120 of 120 fields")).toBeVisible();
  expect(within(pages).getByRole("button", { name: "Last declarations page" })).toBeDisabled();
  const tenth = within(pages).getByRole("button", { name: "Declarations page 10" });
  tenth.focus();
  await user.keyboard("{Enter}");
  expect(screen.getByText("91–100 of 120 fields")).toBeVisible();
  expect(tenth).toHaveAttribute("aria-current", "page");
  await user.click(within(pages).getByRole("button", { name: "Previous declarations" }));
  expect(screen.getByText("81–90 of 120 fields")).toBeVisible();
  await user.click(within(pages).getByRole("button", { name: "First declarations page" }));
  expect(screen.getByText("1–10 of 120 fields")).toBeVisible();
  await user.type(screen.getByRole("textbox", { name: "Search environment origins" }), "value-119");
  expect(screen.getByText("1–1 of 1 fields")).toBeVisible();
  expect(within(pages).getAllByRole("button", { name: /^Declarations page/ })).toHaveLength(1);
  expect(within(pages).getByRole("button", { name: "Last declarations page" })).toBeDisabled();
});
