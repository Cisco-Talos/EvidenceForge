import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, expect, test, vi } from "vitest";
import { EnvironmentView } from "../src/EnvironmentView";
import type { AssetPage, CatalogItem, DependencyRow, EnvironmentReport, StudioApi } from "../src/api";

const item = { id: "scenario", kind: "scenario", source_sha256: "source", name: "Example" } as CatalogItem;
const report: EnvironmentReport = {
  source_sha256: "source", project_root: "/workspace", valid: true, error: "", compiled_sha256: "compiled", authored_kind: "scenario-2.0",
  selected_packs: [{ source: "project", publisher: "team", type: "organization", name: "office", version: "2.0.0", digest: "d".repeat(64), location: "project:team:organization:office@2.0.0" }, { source: "package", publisher: "evidenceforge", type: "industry", name: "healthcare", version: "1.0.0", digest: "a".repeat(64), location: "package:evidenceforge:industry:healthcare@1.0.0" }],
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
  const assets: AssetPage = { revision: "compiled", category: "users", categories: [{ key: "users", label: "Users", total: 0, editable: true }], total: 0, matching: 0, page: 0, page_size: 50, entries: [] };
  const api = { request: vi.fn(async (path: string, ..._args: unknown[]) => {
    if (/^\/v1\/items\/[^/]+\/assets\?/.test(path)) return assets;
    if (/^\/v1\/scenarios\/[^/]+\/configuration$/.test(path)) return {};
    if (/^\/v1\/scenarios\/[^/]+\/environment$/.test(path)) return request();
    throw new Error(`Unexpected test request: ${path}`);
  }), readTextPreview: vi.fn(async () => ({ text: "# Header\n# Context\n\ndomains: []\ndescription: Clinic exercise\n", truncated: false, binary: false })), download: vi.fn(async () => ({ status: "browser" })) } as unknown as StudioApi;
  const onError = vi.fn();
  const props = { item, packs, api, onPrepare, onError, dependencyFingerprint: "deps-1" };
  const view = render(<Tooltip.Provider><EnvironmentView {...props} /></Tooltip.Provider>);
  return { ...view, api, onPrepare, onError, props, environmentRequest: request };
}
afterEach(() => { cleanup(); sessionStorage.clear(); });

test("embedded Environment shows dependency rows directly without readiness or pack disclosures", async () => {
  const request = vi.fn(async () => ({ ...report, valid: false, selected_packs: [], error: "Required pack missing" }));
  const onImportPacks = vi.fn();
  const api = { request } as unknown as StudioApi;
  const health = { ready: false, fingerprint: "missing", changed_at: 0, rows: [
    { key: "ready", kind: "pack" as const, label: "healthcare@1.0.0", status: "available" as const, detail: "Exact version verified" },
    { key: "missing", kind: "pack" as const, label: "office@2.0.0", status: "missing" as const, detail: "Import this version" },
    { key: "include", kind: "include" as const, label: "users.yaml", status: "missing" as const, detail: "Restore included file" },
  ] };
  const props = { embedded: true, item, packs, dependencyHealth: health, api, onPrepare: vi.fn(async () => undefined), onError: vi.fn(), onImportPacks };
  const { rerender } = render(<Tooltip.Provider><EnvironmentView {...props} refreshVersion={0} /></Tooltip.Provider>);
  expect(screen.getByText("healthcare@1.0.0")).toBeVisible();
  expect(screen.getByText("office@2.0.0")).toBeVisible();
  expect(screen.getByText("users.yaml")).toBeVisible();
  expect(screen.queryByText("Dependencies ready")).toBeNull();
  expect(screen.queryByRole("button", { name: "Refresh environment" })).toBeNull();
  expect(screen.queryByRole("button", { name: /Selected packs/ })).toBeNull();
  await userEvent.setup().click(screen.getByRole("button", { name: "Import packs" }));
  expect(onImportPacks).toHaveBeenCalledOnce();
  await waitFor(() => expect(screen.queryByText("Resolving environment…")).toBeNull());
  rerender(<Tooltip.Provider><EnvironmentView {...props} refreshVersion={1} /></Tooltip.Provider>);
  await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
});

test("folded environment inspection headers expose selected values and composition results", async () => {
  setup();
  await screen.findByRole("heading", { name: "Packs 2" });
  expect(screen.getByText("project:team:organization:office@2.0.0")).toBeVisible();
  expect(screen.getByText("package:evidenceforge:industry:healthcare@1.0.0")).toBeVisible();
  expect(screen.queryByRole("button", { name: /Selected packs/ })).toBeNull();
  expect(screen.getByRole("button", { name: "Configuration layers 1 enabled · 2 layers" })).toHaveTextContent("Workspace: 1 file");
  expect(screen.getByRole("button", { name: "Resolved scenario model scenario-2.0" })).toHaveTextContent("1 user");
  expect(screen.getByRole("button", { name: "Overrides and precedence 1 override" })).toHaveTextContent("users → scenario");
  expect(screen.getByText("3 fields · 3 files · 3 layers")).toBeVisible();
});

test("exact versions and source declarations are searchable and refresh after dependency changes", async () => {
  const { environmentRequest, props, rerender } = setup();
  const user = userEvent.setup();
  await screen.findByRole("heading", { name: "Packs 2" });
  expect(screen.getByText("project:team:organization:office@2.0.0")).toBeVisible();
  expect(screen.queryByRole("textbox", { name: "Search environment origins" })).not.toBeInTheDocument();
  await user.click(screen.getByText("Source declarations"));
  await user.type(screen.getByRole("textbox", { name: "Search environment origins" }), "brief.yaml");
  expect(screen.getByText("brief.yaml:5")).toBeVisible();
  expect(screen.getByText("Clinic exercise")).toBeVisible();
  expect(screen.queryByText("office/pack.yaml")).not.toBeInTheDocument();
  rerender(<Tooltip.Provider><EnvironmentView {...props} dependencyFingerprint="deps-2" /></Tooltip.Provider>);
  await waitFor(() => expect(environmentRequest).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.getByRole("button", { name: "Refresh environment" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Refresh environment" }));
  await waitFor(() => expect(environmentRequest).toHaveBeenCalledTimes(3));
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
  await screen.findByText("No assets in this category yet.");
  const user = userEvent.setup();
  await user.click(screen.getByText("Source declarations"));
  const table = screen.getByRole("columnheader", { name: "Field / layer" }).closest("table")!;
  expect(within(table).getAllByRole("row")).toHaveLength(11);
  for (const value of ["false", "0", '""', "null"]) expect(within(table).getByText(value, { exact: true })).toBeVisible();
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
  await screen.findByRole("heading", { name: "Packs 2" });
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
  await screen.findByRole("heading", { name: "Packs 2" });
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
  await screen.findByRole("heading", { name: "Packs 2" });
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Configuration layers 1 enabled · 2 layers" }));
  await user.click(screen.getByText(/^View configuration files/));
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
  await waitFor(() => expect(screen.queryByText("Resolving environment…")).toBeNull());
  expect(screen.getByText(/inline environment; no packs/)).toBeVisible();
  await act(async () => resolveOld(report));
  expect(screen.queryByText("project:team:organization:office@2.0.0")).not.toBeInTheDocument();
});


test("scenario configuration can be toggled and is refreshed before inspection", async () => {
  const { api, environmentRequest } = setup();
  await userEvent.setup().click(await screen.findByRole("button", { name: "Configuration layers 1 enabled · 2 layers" }));
  const checkbox = screen.getByRole("checkbox", { name: "Use Scenario configuration" });
  expect(checkbox).not.toBeChecked();
  await userEvent.setup().click(checkbox);
  await waitFor(() => expect(api.request).toHaveBeenCalledWith("/v1/scenarios/scenario/configuration", "POST", { scenario_enabled: true }));
  await waitFor(() => expect(environmentRequest).toHaveBeenCalledTimes(2));
});


test("inspection sections start folded, expose counts, and expand independently by keyboard", async () => {
  setup();
  const packs = await screen.findByRole("heading", { name: "Packs 2" });
  const layers = screen.getByRole("button", { name: "Configuration layers 1 enabled · 2 layers" });
  const overrides = screen.getByRole("button", { name: "Overrides and precedence 1 override" });
  for (const toggle of [layers, overrides]) expect(toggle).toHaveAttribute("aria-expanded", "false");
  expect(screen.getByText("project:team:organization:office@2.0.0")).toBeVisible();
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
  await screen.findByText("No assets in this category yet.");
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

test("environment dependency links open the exact industry and organization packs by keyboard and click", async () => {
  const { props, rerender } = setup();
  const onOpenPack = vi.fn();
  const office = { ...packs[0], id: "office-exact", path: "/workspace/office/pack.yaml", hidden: true };
  const industry = { ...packs[2], id: "industry-exact", path: "/package/pack.yaml" };
  const candidates = [
    { ...office, id: "newer-office", version: "3.0.0", path: "/workspace/newer/pack.yaml" },
    { ...industry, id: "workspace-copy", pack_source: "workspace" as const, path: "/workspace/copy/pack.yaml" },
    { ...industry, id: "other-publisher", publisher: "other", path: "/other/pack.yaml" },
    office, industry,
  ];
  const rows: DependencyRow[] = report.selected_packs.map((pack) => ({ key: `${pack.publisher}:${pack.type}:${pack.name}@${pack.version}`, kind: "pack", label: `${pack.publisher}:${pack.type}:${pack.name}@${pack.version}`, status: "available", detail: "Exact pack is available", digest: pack.digest }));
  rows.push({ key: "team:organization:office@9.0.0", kind: "pack", label: "team:organization:office@9.0.0", status: "missing", detail: "Import exact version", digest: "missing" });
  rerender(<Tooltip.Provider><EnvironmentView {...props} packs={candidates} onOpenPack={onOpenPack} dependencyHealth={{ ready: false, fingerprint: "deps", changed_at: 0, rows }} /></Tooltip.Provider>);
  const orgLink = await screen.findByRole("button", { name: "Open team:organization:office@2.0.0 pack workspace" });
  orgLink.focus();
  await userEvent.setup().keyboard("{Enter}");
  expect(onOpenPack).toHaveBeenLastCalledWith(office);
  await userEvent.setup().click(screen.getByRole("button", { name: "Open evidenceforge:industry:healthcare@1.0.0 pack workspace" }));
  expect(onOpenPack).toHaveBeenLastCalledWith(industry);
  expect(screen.getByText("team:organization:office@9.0.0")).toBeVisible();
  expect(screen.queryByRole("button", { name: /Open .*office@9/ })).toBeNull();
});

test("resolved pack cards link to indexed locations and never substitute another copy for an external path", async () => {
  const selected = [
    { ...report.selected_packs[0], source: "path" as const, location: "/external/office" },
    report.selected_packs[1],
  ];
  const { props, rerender } = setup(vi.fn(async () => ({ ...report, selected_packs: selected })));
  const onOpenPack = vi.fn();
  const industry = { ...packs[2], id: "bundled", path: "/package/pack.yaml" };
  rerender(<Tooltip.Provider><EnvironmentView {...props} packs={[{ ...packs[0], id: "office", path: "/workspace/office/pack.yaml" }, industry]} onOpenPack={onOpenPack} /></Tooltip.Provider>);
  await userEvent.setup().click(await screen.findByRole("button", { name: "Open evidenceforge:industry:healthcare@1.0.0 pack workspace" }));
  expect(onOpenPack).toHaveBeenCalledWith(industry);
  expect(screen.getByText("/external/office")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Open team:organization:office@2.0.0 pack workspace" })).toBeNull();
});

test("resolved dependency locations stay navigable when composition fails and distinguish identical pack identities", async () => {
  const { props, rerender } = setup(vi.fn(async () => ({ ...report, valid: false, selected_packs: [], error: "An unrelated include is missing" })));
  const onOpenPack = vi.fn();
  const industry = { ...packs[2], id: "selected", path: "/package/pack.yaml" };
  const rows: DependencyRow[] = [
    { key: "evidenceforge:industry:healthcare@1.0.0", kind: "pack", label: "evidenceforge:industry:healthcare@1.0.0", status: "available", detail: "Exact pack is available", source: industry.path },
    { key: "team:organization:office@2.0.0", kind: "pack", label: "team:organization:office@2.0.0", status: "conflict", detail: "Digest mismatch", source: "/workspace/office/pack.yaml" },
  ];
  const office = { ...packs[0], id: "office", path: "/workspace/office/pack.yaml" };
  rerender(<Tooltip.Provider><EnvironmentView {...props} packs={[{ ...industry, id: "workspace-copy", pack_source: "workspace", path: "/workspace/copy/pack.yaml" }, { ...industry, id: "other-root", path: "/other-package/pack.yaml" }, industry, office]} onOpenPack={onOpenPack} dependencyHealth={{ ready: false, fingerprint: "deps", rows }} /></Tooltip.Provider>);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Open evidenceforge:industry:healthcare@1.0.0 pack workspace" }));
  expect(onOpenPack).toHaveBeenLastCalledWith(industry);
  await screen.findByText(/An unrelated include is missing/);
  await user.click(screen.getByRole("button", { name: "Open team:organization:office@2.0.0 pack workspace" }));
  expect(onOpenPack).toHaveBeenLastCalledWith(office);
});
