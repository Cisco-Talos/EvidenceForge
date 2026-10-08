import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { AssetBrowser } from "../src/AssetBrowser";
import type { AssetDetail, AssetPage, CatalogItem, StudioApi } from "../src/api";
import schemas from "./fixtures/asset-schemas.json";

const item = { id: "assets-example", kind: "scenario", source_sha256: "source" } as CatalogItem;
const origin = { kind: "mixed" as const, source: "team/office@1.0.0 · scenario.yaml" };
const detail: AssetDetail = { revision: "revision", summary: { id: "user-0", key: "alice", name: "alice", description: "alice@example.com", origin }, category: "users", identity_field: "username", value: { username: "alice", full_name: "Alice Original", email: "alice@example.com" }, field_origins: { username: { kind: "pack", source: "team/office@1.0.0" }, full_name: { kind: "scenario", source: "scenario.yaml" }, email: { kind: "pack", source: "team/office@1.0.0" } }, schema_document: { type: "object", properties: { username: { type: "string", title: "Username" }, full_name: { type: "string", title: "Full name" }, email: { type: "string", title: "Email" } }, required: ["username", "full_name", "email"] }, next_version: null };
function setup(selected = item) {
  const request = vi.fn(async (path: string, method?: string) => {
    if (method === "POST") return { path: "/workspace/scenario.yaml" };
    if (path.includes("/detail?")) return { ...detail, next_version: selected.kind === "scenario" ? null : "1.0.1" };
    const params = new URLSearchParams(path.split("?")[1]);
    const size = Number(params.get("page_size") || 50);
    const page = Number(params.get("page") || 0);
    const query = params.get("query");
    const rows = Array.from({ length: 1005 }, (_, index) => ({ ...detail.summary!, id: `user-${index}`, key: index ? `user${index}` : "alice", name: index ? `user${index}` : "alice" }));
    const matching = query ? rows.filter((row) => row.name.includes(query)) : rows;
    const current = Math.min(page, Math.max(0, Math.ceil(matching.length / size) - 1));
    return { revision: "revision", category: "users", categories: [{ key: "users", label: "Users", total: 1005, editable: true }], total: 1005, matching: matching.length, page: current, page_size: size, entries: matching.slice(current * size, (current + 1) * size) } as AssetPage;
  });
  const api = { request } as unknown as StudioApi;
  const onChanged = vi.fn(async () => undefined);
  const view = render(<Tooltip.Provider><AssetBrowser item={selected} api={api} onChanged={onChanged} /></Tooltip.Provider>);
  return { ...view, request, onChanged, api };
}
beforeEach(() => { vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} }); });
afterEach(() => { cleanup(); sessionStorage.clear(); vi.unstubAllGlobals(); });

test("large lists are bounded and reuse numbered pagination; details load only on expansion", async () => {
  const { request } = setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "alice" });
  expect(screen.getAllByRole("row")).toHaveLength(51);
  expect(request.mock.calls.some(([path]) => path.includes("/detail?"))).toBe(false);
  await user.click(screen.getByRole("button", { name: "alice" }));
  expect(await screen.findByText("Alice Original")).toBeVisible();
  expect(request.mock.calls.filter(([path]) => path.includes("/detail?")).length).toBe(1);
  const pages = screen.getByRole("navigation", { name: "Asset pages" });
  await user.click(within(pages).getByRole("button", { name: "Last assets page" }));
  await screen.findByText("1001–1005 of 1005 assets");
  expect(screen.getAllByRole("row")).toHaveLength(6);
  expect(screen.queryByText("Alice Original")).not.toBeInTheDocument();
  await user.type(screen.getByRole("textbox", { name: "Search assets" }), "user1004");
  await screen.findByText("1–1 of 1 assets");
  expect(screen.getByText("1 matching · 1,005 total")).toBeVisible();
});

test("origin badges are graphical and explain their color on keyboard focus", async () => {
  setup(); const user = userEvent.setup();
  await screen.findByRole("button", { name: "alice" });
  const badge = screen.getAllByLabelText("Pack with scenario overrides: team/office@1.0.0 · scenario.yaml")[0];
  expect(badge.textContent).toBe("");
  expect(screen.getAllByRole("row")[1].children[0]).toContainElement(badge);
  badge.focus();
  expect(await screen.findByRole("tooltip")).toHaveTextContent("Pack with scenario overrides");
  await user.click(screen.getByRole("button", { name: "alice" }));
  await screen.findByText("Alice Original");
  expect(screen.getByLabelText("Scenario: scenario.yaml")).toBeVisible();
  expect(screen.getAllByLabelText("Pack: team/office@1.0.0")).toHaveLength(2);
});

function guidedSetup(selectedDetail: AssetDetail, choices: Record<string, string[]> = {}) {
  const request = vi.fn(async (path: string, method?: string) => {
    if (method === "POST") return { path: "/workspace/scenario.yaml" };
    const params = new URLSearchParams(path.split("?")[1]);
    if (path.includes("/choices?")) {
      const values = (choices[params.get("source") || ""] || []).filter((entry) => entry.includes(params.get("query") || ""));
      const page = Number(params.get("page") || 0);
      return { revision: "revision", page, page_size: 50, matching: values.length, entries: values.slice(page * 50, (page + 1) * 50) };
    }
    if (path.includes("/detail?")) return { ...selectedDetail, summary: params.get("asset_id") ? selectedDetail.summary : null, value: params.get("asset_id") ? selectedDetail.value : {} };
    const entries = selectedDetail.summary ? [selectedDetail.summary] : [];
    return { revision: "revision", category: selectedDetail.category, categories: [{ key: selectedDetail.category, label: selectedDetail.category, total: entries.length, editable: true }], total: entries.length, matching: entries.length, page: 0, page_size: 50, entries } as AssetPage;
  });
  render(<Tooltip.Provider><AssetBrowser item={item} api={{ request } as unknown as StudioApi} /></Tooltip.Provider>);
  return request;
}

test("constrained fields use searchable reference choices and enum selectors", async () => {
  const referenceDetail = { ...detail, schema_document: schemas.user, value: { ...detail.value, groups: ["sales"], enabled: true, primary_system: "HOST-0000", persona: "developer", browsing_intensity: "normal" } };
  const request = guidedSetup(referenceDetail, { systems: Array.from({ length: 1005 }, (_, index) => `HOST-${String(index).padStart(4, "0")}`), groups: ["sales", "engineering"], personas: ["developer", "analyst"] });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "alice" }));
  expect(await screen.findByText("sales")).toHaveClass("asset-value-tag");
  expect(screen.queryByText('[\n  "sales"\n]')).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Customize in scenario" }));
  expect(screen.getByRole("combobox", { name: "Browsing Intensity" })).toHaveValue("normal");
  await user.selectOptions(screen.getByRole("combobox", { name: "Browsing Intensity" }), "heavy");
  await user.click(screen.getByRole("button", { name: "Choose Primary System" }));
  await screen.findByRole("option", { name: "HOST-0000" });
  expect(screen.getAllByRole("option").filter((entry) => entry.tagName === "BUTTON")).toHaveLength(50);
  await user.type(screen.getByRole("textbox", { name: "Search Primary System choices" }), "HOST-1004");
  await user.click(await screen.findByRole("option", { name: "HOST-1004" }));
  await user.click(screen.getByRole("button", { name: "Choose Groups" }));
  await user.click(await screen.findByRole("option", { name: /engineering/ }));
  await user.click(screen.getByRole("button", { name: "Close choices" }));
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  expect(request).toHaveBeenCalledWith(expect.any(String), "POST", expect.objectContaining({ value: expect.objectContaining({ primary_system: "HOST-1004", groups: ["sales", "engineering"], browsing_intensity: "heavy" }) }), 180000);
});

test("application platform dictionaries show nested fields and save exact nested edits", async () => {
  const application: AssetDetail = { ...detail, category: "applications", identity_field: "id", schema_document: schemas.application, summary: { ...detail.summary!, id: "app", key: "browser", name: "Browser" }, value: { id: "browser", display_name: "Browser", categories: ["browser"], personas: ["developer"], platforms: { windows: { image_path: "C:\\Browser\\browser.exe", deployment: { kind: "legacy_static" }, command_templates: ["browser.exe --new-window"] }, linux: { image_path: "/usr/bin/browser", deployment: { kind: "legacy_static" } } } } };
  const request = guidedSetup(application);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Browser" }));
  expect(await screen.findByText("C:\\Browser\\browser.exe")).toBeVisible();
  expect(screen.getByText("Windows")).toBeVisible();
  expect(screen.getAllByRole("textbox")).toHaveLength(2);
  await user.click(screen.getByRole("button", { name: "Customize in scenario" }));
  const image = screen.getByRole("textbox", { name: "Platforms / Windows / Image Path *" });
  await user.clear(image); await user.type(image, "C:\\Browser\\browser-v2.exe");
  expect(screen.queryByRole("textbox", { name: "Platforms" })).not.toBeInTheDocument();
  expect(screen.queryByRole("combobox", { name: "Platforms / Windows / Deployment definition type" })).not.toBeInTheDocument();
  await user.click(screen.getAllByText("Edit deployment")[0]);
  expect(await screen.findByRole("combobox", { name: "Platforms / Windows / Deployment definition type" })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  expect(request).toHaveBeenCalledWith(expect.any(String), "POST", expect.objectContaining({ value: expect.objectContaining({ platforms: { ...application.value.platforms as object, windows: { ...((application.value.platforms as Record<string, object>).windows), image_path: "C:\\Browser\\browser-v2.exe" } } }) }), 180000);
});

test("Add Asset explains the selected type and blocks missing required fields", async () => {
  const request = guidedSetup({ ...detail, schema_document: schemas.user });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "alice" });
  await user.click(await screen.findByRole("button", { name: "Add asset" }));
  expect(await screen.findByRole("region", { name: "Choose asset type" })).toBeVisible();
  expect(screen.getByRole("combobox", { name: "Account kind" })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Continue with user account" }));
  await screen.findByRole("form", { name: "Add user account" });
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  expect(screen.getByRole("alert")).toHaveTextContent("Username is required");
  expect(screen.queryByRole("button", { name: "Save draft" })).not.toBeInTheDocument();
  await user.type(screen.getByRole("textbox", { name: "Username *" }), "new.user");
  await user.type(screen.getByRole("textbox", { name: "Full Name *" }), "New User");
  await user.type(screen.getByRole("textbox", { name: "Email *" }), "invalid-address");
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  expect(screen.getByRole("alert")).toHaveTextContent("Email needs a valid email address");
  await user.clear(screen.getByRole("textbox", { name: "Email *" }));
  await user.type(screen.getByRole("textbox", { name: "Email *" }), "new@example.com");
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  expect(request).toHaveBeenCalledWith(expect.any(String), "POST", expect.objectContaining({ asset_id: null, category: "users", key: "new.user", value: expect.objectContaining({ username: "new.user", email: "new@example.com" }) }), 180000);
});

test("scenario editing reviews a concrete change and submits a revision guard", async () => {
  const { request, onChanged } = setup(); const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "alice" }));
  await user.click(await screen.findByRole("button", { name: "Customize in scenario" }));
  expect(screen.getByLabelText("Username *")).toBeDisabled();
  const field = screen.getByLabelText("Full name *");
  await user.clear(field); await user.type(field, "Alice Local");
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  expect(screen.getByText("Alice Original")).toBeVisible();
  expect(screen.getByText("Alice Local")).toBeVisible();
  expect(request.mock.calls.some(([, method]) => method === "POST")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
  expect(request).toHaveBeenCalledWith("/v1/items/assets-example/assets", "POST", expect.objectContaining({ revision: "revision", category: "users", asset_id: "user-0", value: expect.objectContaining({ full_name: "Alice Local" }), version: null }), 180000);
});

test("pack editing requires a new version and remembers page state on reopen", async () => {
  const selected = { ...item, kind: "organization_pack" } as CatalogItem;
  const { unmount, api } = setup(selected); const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "alice" }));
  await user.click(await screen.findByRole("button", { name: "Edit" }));
  expect(screen.getByLabelText("New version")).toHaveValue("1.0.1");
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  await user.click(screen.getByRole("button", { name: "Last assets page" }));
  await screen.findByText("1001–1005 of 1005 assets");
  unmount(); render(<Tooltip.Provider><AssetBrowser item={selected} api={api} /></Tooltip.Provider>);
  expect(await screen.findByText("1001–1005 of 1005 assets")).toBeVisible();
});

const inheritedUser = { username: "alice", full_name: "Alice Pack", email: "alice@example.com", groups: ["sales"], enabled: true, persona: "developer", primary_system: null, browsing_intensity: "normal" };
const customizedUser: AssetDetail = { ...detail, schema_document: schemas.user, inherited_value: inheritedUser, override_fields: ["full_name", "groups.0"], value: { ...inheritedUser, full_name: "Alice Local", groups: ["engineering"] } };

test("customized fields are marked and restoring a field previews inherited values", async () => {
  const request = guidedSetup(customizedUser, { groups: ["sales", "engineering"] });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "alice" }));
  expect(await screen.findByRole("button", { name: "Restore inherited values" })).toBeVisible();
  expect(screen.getAllByText("Customized")).toHaveLength(2);
  await user.click(screen.getByRole("button", { name: "Customize in scenario" }));
  expect(screen.getByRole("combobox", { name: "Account status" })).toHaveValue("true");
  expect(within(screen.getByRole("combobox", { name: "Account status" })).getByRole("option", { name: "Active", exact: true })).toBeVisible();
  const restore = screen.getByRole("button", { name: "Restore inherited Groups" });
  expect(restore.closest(".asset-form-field")).toHaveClass("asset-field-customized");
  expect(screen.queryByText("Use default")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Reset Groups to field default" }));
  expect(screen.queryByText("engineering")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Restore inherited Groups" }));
  expect(screen.getByText("sales")).toBeVisible();
  expect(screen.getByText("Restoring")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  expect(screen.getByText(/marked overrides will be removed/)).toBeVisible();
  expect(request.mock.calls.some(([, method]) => method === "POST")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  expect(request).toHaveBeenCalledWith(expect.any(String), "POST", expect.objectContaining({ restore_fields: ["groups"], value: expect.objectContaining({ groups: ["sales"], full_name: "Alice Local" }) }), 180000);
});

test("restoring the whole asset is reviewed and subsequent edits preserve other restorations", async () => {
  const request = guidedSetup(customizedUser);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "alice" }));
  await user.click(await screen.findByRole("button", { name: "Restore inherited values" }));
  expect(screen.getByText(/All scenario customizations on this asset will be removed/)).toBeVisible();
  expect(screen.getByText("Alice Pack")).toBeVisible();
  expect(request.mock.calls.some(([, method]) => method === "POST")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Back to edit" }));
  const name = screen.getByRole("textbox", { name: "Full Name *" });
  await user.clear(name); await user.type(name, "Alice revised");
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  const payload = request.mock.calls.find(([, method]) => method === "POST")?.[2] as unknown as { restore_fields: string[]; value: Record<string, unknown> };
  expect(payload.restore_fields).toContain("groups");
  expect(payload.restore_fields).not.toContain("username");
  expect(payload.restore_fields).not.toContain("full_name");
  expect(payload.value.full_name).toBe("Alice revised");
  expect(payload.value.groups).toEqual(["sales"]);
});


function conversionSetup(from: "users" | "stale_accounts", errors: string[] = []) {
  const ordinary = { username: "alice", full_name: "Alice Saved", email: "alice@example.com", enabled: false, groups: ["sales"], primary_system: "HOST-1" };
  const stale = { username: "alice", last_active: "2024-01-14", reason: "Former employee" };
  const staleSchema = { type: "object", properties: { username: { type: "string" }, last_active: { type: "string", format: "date" }, reason: { type: "string" } }, required: ["username", "last_active", "reason"] };
  const current: AssetDetail = { ...detail, category: from, value: from === "users" ? ordinary : stale, schema_document: from === "users" ? schemas.user : staleSchema };
  const target = from === "users" ? "stale_accounts" : "users";
  const draft: AssetDetail = { ...current, category: target, schema_document: target === "users" ? schemas.user : staleSchema, value: target === "users" ? ordinary : stale, previous_value: current.value, conversion_from: from, conversion_effects: ["Remove membership in group sales"] };
  const request = vi.fn(async (path: string, method?: string, body?: unknown) => {
    if (method === "POST") return { path: "/workspace/scenario.yaml", validation_errors: (body as { preview?: boolean }).preview ? errors : [], effects: ["Remove membership in group sales"] };
    if (path.includes("/detail?")) return path.includes("conversion=true") ? draft : current;
    return { revision: "revision", category: "users", categories: [{ key: "users", label: "Users", total: 1, editable: true }], total: 1, matching: 1, page: 0, page_size: 50, entries: [current.summary] } as AssetPage;
  });
  const onChanged = vi.fn(async () => undefined);
  render(<Tooltip.Provider><AssetBrowser item={item} api={{ request } as unknown as StudioApi} onChanged={onChanged} /></Tooltip.Provider>);
  return { request, onChanged };
}

test("retirement checks references without saving, then reviews status and directory links", async () => {
  const { request, onChanged } = conversionSetup("users");
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "alice" }));
  await user.click(await screen.findByRole("button", { name: "Mark as stale…" }));
  expect(await screen.findByRole("heading", { name: "Mark as stale: alice" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Username *" })).toBeDisabled();
  await user.clear(screen.getByRole("textbox", { name: "Reason *" }));
  await user.type(screen.getByRole("textbox", { name: "Reason *" }), "Retired test account");
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  expect(await screen.findByRole("heading", { name: "Review account conversion" })).toBeVisible();
  expect(screen.getByText("Remove membership in group sales")).toBeVisible();
  expect(screen.getByText(/Disabled → Stale/)).toBeVisible();
  expect(onChanged).not.toHaveBeenCalled();
  expect(request).toHaveBeenCalledWith(expect.any(String), "POST", expect.objectContaining({ preview: true, convert_from: "users", category: "stale_accounts", value: expect.objectContaining({ reason: "Retired test account" }) }), 180000);
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
  const posts = request.mock.calls.filter(([, method]) => method === "POST");
  expect(posts).toHaveLength(2);
  expect(posts[1][2]).not.toHaveProperty("preview");
});

test("restoration fills saved user details and permits choosing active or disabled", async () => {
  const { request } = conversionSetup("stale_accounts");
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "alice" }));
  await user.click(await screen.findByRole("button", { name: "Restore as user…" }));
  expect(await screen.findByRole("textbox", { name: "Full Name *" })).toHaveValue("Alice Saved");
  expect(screen.getByRole("combobox", { name: "Account status" })).toHaveValue("false");
  await user.selectOptions(screen.getByRole("combobox", { name: "Account status" }), "true");
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  expect(await screen.findByText(/Stale → Active/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  expect(request.mock.calls.filter(([, method]) => method === "POST")[1][2]).toEqual(expect.objectContaining({ convert_from: "stale_accounts", category: "users", value: expect.objectContaining({ enabled: true, full_name: "Alice Saved", groups: ["sales"], primary_system: "HOST-1" }) }));
});

test("conversion review shows canonical blockers and disables saving", async () => {
  const { request, onChanged } = conversionSetup("users", ["storyline.0.actor: Unknown actor alice"]);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "alice" }));
  await user.click(await screen.findByRole("button", { name: "Mark as stale…" }));
  await screen.findByRole("heading", { name: "Mark as stale: alice" });
  await user.click(screen.getByRole("button", { name: "Review changes" }));
  expect(await screen.findByText("storyline.0.actor: Unknown actor alice")).toBeVisible();
  expect(screen.getByRole("button", { name: "Save draft" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(request.mock.calls.filter(([, method]) => method === "POST")).toHaveLength(1);
  expect(onChanged).not.toHaveBeenCalled();
});
