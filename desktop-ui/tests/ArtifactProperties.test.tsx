import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, expect, test, vi } from "vitest";
import { ArtifactPropertiesDialog, BundlePropertiesDialog } from "../src/ArtifactProperties";
import type { CatalogItem, StudioApi, StudioSnapshot } from "../src/api";

afterEach(cleanup);
const item = { id: "draft", name: "stable-id", display_name: "Friendly title", kind: "scenario", source_sha256: "source", path: "/draft/scenario.yaml" } as CatalogItem;
const draft = { kind: "scenario", name: item.name, display_name: item.display_name, description: "Overview", digest: "captured", schema_version: "3.0", path: item.path, lifecycle: { status: "draft", draft_id: "draft-id", release_notes: "Current notes", parents: [] }, history: [{ name: item.name, publisher: "team", version: "1.0.0", status: "published", digest: "older", notes: "Earlier notes", available: true }], dependencies: [], comparisons: [], source_files: [item.path], findings: [] };
function fixture(properties = draft) {
  const request = vi.fn(async (path: string, method?: string, body?: unknown) => {
    if (path === "/v1/assist/display-name") return { display_name: "AI title" };
    if (path === "/v1/assist/description") return { description: "AI overview" };
    if (path.endsWith("/properties") && method === "PATCH") return { path: item.path };
    if (path.includes("/lifecycle")) return { digest: properties.digest, lifecycle: properties.lifecycle, versions: [] };
    void body; return properties;
  });
  const onClose = vi.fn(); const onChanged = vi.fn(async () => undefined); const onOpen = vi.fn(async () => undefined);
  render(<Tooltip.Provider><ArtifactPropertiesDialog item={item} snapshot={{ projects: [] } as unknown as StudioSnapshot} api={{ request } as unknown as StudioApi} onClose={onClose} onChanged={onChanged} onOpen={onOpen} onProjectChange={vi.fn()} /></Tooltip.Provider>);
  return { request, onClose, onChanged, onOpen, user: userEvent.setup() };
}

test("direct property edits preserve identifier and require reviewed save; escape offers discard", async () => {
  const { user, request, onClose } = fixture();
  const title = await screen.findByRole("textbox", { name: "Display name" });
  expect(title).toHaveValue("Friendly title");
  await user.clear(title); await user.type(title, "Manual title");
  await user.keyboard("{Escape}");
  expect(onClose).not.toHaveBeenCalled();
  expect(screen.getByText("Discard unsaved property changes?")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Keep editing" }));
  await user.click(screen.getByRole("button", { name: "Save properties" }));
  expect(request).toHaveBeenCalledWith("/v1/items/draft/properties", "PATCH", { display_name: "Manual title", description: "Overview", release_notes: "Current notes", expected_digest: "captured" });
  expect(request.mock.calls.some(([, method]) => method === "POST")).toBe(false);
});

test("title assistance is editable preview, explicit acceptance and separate persistence", async () => {
  const { user, request } = fixture();
  const title = await screen.findByRole("textbox", { name: "Display name" });
  await user.click(screen.getByRole("button", { name: "Suggest display name with AI" }));
  const preview = await screen.findByRole("region", { name: "AI display name preview" });
  expect(title).toHaveValue("Friendly title");
  await user.clear(within(preview).getByRole("textbox")); await user.type(within(preview).getByRole("textbox"), "Reviewed title");
  await user.click(within(preview).getByRole("button", { name: "Use suggestion" }));
  expect(title).toHaveValue("Reviewed title");
  expect(request.mock.calls.some(([, method]) => method === "PATCH")).toBe(false);
});

test("stale saves retain manual edits and never refresh or retry them automatically", async () => {
  const { user, request } = fixture();
  const title = await screen.findByRole("textbox", { name: "Display name" });
  await user.clear(title); await user.type(title, "Keep this title");
  request.mockRejectedValueOnce(new Error("source changed after review"));
  await user.click(screen.getByRole("button", { name: "Save properties" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("source changed");
  expect(title).toHaveValue("Keep this title");
  expect(screen.getByRole("button", { name: "Refresh properties" })).toBeDisabled();
  expect(request.mock.calls.filter(([, method]) => method === "PATCH")).toHaveLength(1);
});

test.each(["identifier", "publisher"])("identity pencils review inputs before changing %s", async (field) => {
  const { user, request } = fixture();
  await screen.findByRole("textbox", { name: "Display name" });
  await user.click(screen.getByRole("button", { name: `Change ${field}` }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/items/draft/lifecycle?names=true"));
  expect(screen.getByRole("textbox", { name: "New identifier" })).toHaveValue("stable-id");
  expect(screen.getByRole("textbox", { name: "New publisher" })).toHaveValue("");
  expect(screen.getByRole("button", { name: "Create linked draft" })).toBeDisabled();
  expect(request.mock.calls.some(([, method]) => method === "POST")).toBe(false);
});

test("published properties are read-only and history exposes available notes separately", async () => {
  const { user } = fixture({ ...draft, lifecycle: { ...draft.lifecycle, status: "published" } });
  expect(await screen.findByRole("textbox", { name: "Display name" })).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Save properties" })).toBeNull();
  await user.click(screen.getByRole("button", { name: "Versions & publication" }));
  expect(screen.queryByText("Earlier notes")).toBeNull();
  await user.click(screen.getByRole("button", { name: "View full history" }));
  expect(screen.getByText("Earlier notes")).toBeVisible();
});

test("both artifact kinds show validation engine provenance without editing schema", async () => {
  for (const kind of ["scenario", "organization"]) {
    const { user } = fixture({ ...draft, kind, validated_with: { evidenceforge_version: "2.1.2", completed_at: "2026-10-08T12:00:00Z", input_digest: "validated", warnings: 1 } } as typeof draft);
    await screen.findByRole("textbox", { name: "Display name" });
    await user.click(screen.getByRole("button", { name: "Technical details" }));
    expect(screen.getByText(/EvidenceForge 2.1.2/)).toBeVisible();
    expect(screen.queryByRole("textbox", { name: "Schema" })).toBeNull();
    cleanup();
  }
});

test("bundle technical details show aggregate data, disk size and present log types separately from captured selections", async () => {
  const request = vi.fn(async () => ({ path: "/bundle", complete: true, size_bytes: 4096, data_bytes: 2048, data_files: 5, scenario: "Captured", evidenceforge_version: "2.1.2", formats: ["windows", "zeek"], log_types: ["zeek_conn", "windows_event_security"], unrecognized_data_files: 1, selected_packs: [], artifact: {}, overrides: {}, findings: [] }));
  render(<Tooltip.Provider><BundlePropertiesDialog id="run" api={{ request } as unknown as StudioApi} onClose={vi.fn()} /></Tooltip.Provider>);
  await screen.findByRole("heading", { name: "Captured" });
  await userEvent.setup().click(screen.getByRole("button", { name: "Technical details" }));
  expect(screen.getByText("2.0 KB · 5 files")).toBeVisible();
  expect(screen.getByText("4.0 KB")).toBeVisible();
  expect(screen.getByText("Zeek · conn")).toBeVisible();
  expect(screen.getByText("Windows Security events")).toBeVisible();
  expect(screen.queryByText("Sysmon")).toBeNull();
  expect(screen.queryByText("EDR (eCAR)")).toBeNull();
  expect(screen.queryByText("Zeek · dns")).toBeNull();
  expect(screen.getByText("1 data file has an unrecognized log type.")).toBeVisible();
  await userEvent.setup().click(screen.getByRole("button", { name: "Captured inputs" }));
  expect(screen.getByText("Windows (Security & Sysmon)")).toBeVisible();
  expect(screen.getByText("Zeek")).toBeVisible();
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/jobs/run/properties"));
});
