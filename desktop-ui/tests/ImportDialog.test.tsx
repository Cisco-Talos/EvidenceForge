import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { ImportDialog } from "../src/ImportDialog";
import { DependencyPanel } from "../src/DependencyPanel";
import type { ImportReview, StudioApi } from "../src/api";

vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => Boolean(window.__TAURI_INTERNALS__), invoke: vi.fn() }));
afterEach(() => { cleanup(); vi.clearAllMocks(); delete window.__TAURI_INTERNALS__; });

const review: ImportReview = {
  id: "review-1", kind: "scenario", name: "imported", destination: "/workspace/scenarios/imported",
  rows: [
    { key: "yaml", kind: "include", label: "scenario.yaml", status: "copy", detail: "Copy source YAML", source: "/source/scenario.yaml" },
    { key: "pack", kind: "pack", label: "example:industry:healthcare@1.0.0", status: "missing", detail: "Import this exact version" },
  ],
  documents: ["ENVIRONMENT.md", "NOTES.md"], publishers: [], can_import: true,
};

function fixture(kind: "scenario" | "pack" = "scenario", next: ImportReview = review) {
  const request = vi.fn(async (path: string, _method?: string, _body?: unknown) => {
    if (path.endsWith("/preview")) return next;
    if (path.endsWith("/validate")) return { exit_code: 1, report: null, error: "Advisory finding" };
    if (path.endsWith("/commit")) return { item: null, packs: 0 };
    return {};
  });
  const api = { request } as unknown as StudioApi;
  const onCreate = vi.fn(async (_name: string, _project: string) => undefined);
  const onImported = vi.fn(async () => undefined);
  const onClose = vi.fn();
  render(<ImportDialog kind={kind} api={api} projects={[{ id: "project", workspace: "/workspace", name: "Training", description: "", created_at: 0, updated_at: 0 }]} onCreate={onCreate} onImported={onImported} onClose={onClose} />);
  return { api, request, onCreate, onImported, onClose, user: userEvent.setup() };
}

async function selectImport(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Choose scenario action" }));
  await user.click(screen.getByRole("menuitemradio", { name: "Import scenario" }));
}

async function openReview() {
  const fixtureState = fixture();
  await fixtureState.user.type(screen.getByRole("textbox", { name: "Scenario Name" }), "imported");
  await selectImport(fixtureState.user);
  await fixtureState.user.type(screen.getByRole("textbox", { name: "Scenario YAML" }), "/source/scenario.yaml");
  await fixtureState.user.click(screen.getByRole("button", { name: "Import scenario" }));
  await screen.findByRole("heading", { name: "Review import" });
  return fixtureState;
}

test("Create is the default and name validation gates both actions", async () => {
  const { user, onCreate, request } = fixture();
  expect((screen.getByRole("button", { name: "Create scenario" }) as HTMLButtonElement).disabled).toBe(true);
  await user.type(screen.getByRole("textbox", { name: "Scenario Name" }), "invalid name");
  expect(screen.getByRole("status").textContent).toMatch(/letters|spaces/);
  await selectImport(user);
  await user.type(screen.getByRole("textbox", { name: "Scenario YAML" }), "/source/scenario.yaml");
  expect((screen.getByRole("button", { name: "Import scenario" }) as HTMLButtonElement).disabled).toBe(true);
  await user.clear(screen.getByRole("textbox", { name: "Scenario Name" }));
  await user.type(screen.getByRole("textbox", { name: "Scenario Name" }), "valid-name");
  await user.click(screen.getByRole("button", { name: "Choose scenario action" }));
  await user.click(screen.getByRole("menuitemradio", { name: "Create scenario" }));
  await user.selectOptions(screen.getByRole("combobox", { name: "Project for new scenario" }), "project");
  await user.click(screen.getByRole("button", { name: "Create scenario" }));
  expect(onCreate).toHaveBeenCalledWith("valid-name", "project");
  expect(request).not.toHaveBeenCalled();
});

test("review exposes copy and missing statuses without automatically validating", async () => {
  const { user, request, onImported } = await openReview();
  expect(screen.getByLabelText("copy")).toBeTruthy();
  expect(screen.getByLabelText("missing")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Copy scenario.yaml source path" })).toBeTruthy();
  expect(request.mock.calls.some(([path]) => path.endsWith("/validate"))).toBe(false);
  await user.click(screen.getByRole("button", { name: "Import with dependency errors" }));
  expect(request).toHaveBeenCalledWith("/v1/imports/review-1/commit", "POST", { accepted_publishers: [] }, 180000);
  expect(onImported).toHaveBeenCalledWith(null);
});

test("optional validation findings do not disable import", async () => {
  const { user, request } = await openReview();
  await user.click(screen.getByRole("button", { name: "Validate prepared scenario" }));
  expect(await screen.findByText("Advisory finding")).toBeTruthy();
  expect((screen.getByRole("button", { name: "Import with dependency errors" }) as HTMLButtonElement).disabled).toBe(false);
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(request).toHaveBeenCalledWith("/v1/imports/review-1", "DELETE");
});

test("multiple source workspaces and document choices are retained in a fresh review", async () => {
  const { user, request } = await openReview();
  await user.click(screen.getByText(/Supporting documents/));
  await user.click(screen.getByRole("checkbox", { name: "NOTES.md" }));
  await user.click(screen.getByText("Source workspaces for missing packs"));
  await user.click(screen.getByRole("button", { name: "Add source workspace" }));
  await user.type(screen.getByRole("textbox", { name: "Source workspace 1" }), "/one");
  await user.click(screen.getByRole("button", { name: "Add source workspace" }));
  await user.type(screen.getByRole("textbox", { name: "Source workspace 2" }), "/two");
  await user.click(screen.getByRole("button", { name: "Import scenario" }));
  expect(request).toHaveBeenLastCalledWith("/v1/imports/scenario/preview", "POST", {
    path: "/source/scenario.yaml", name: "imported", project_id: null,
    source_workspaces: ["/one", "/two"], documents: ["ENVIRONMENT.md"],
  }, 180000);
});

test("pack conflicts disable import while preserving review and cancellation", async () => {
  const { user, request, onClose } = fixture("pack", { ...review, kind: "pack", can_import: false, documents: [], publishers: ["example"], rows: [{ key: "conflict", kind: "pack", label: "example:industry:healthcare@1.0.0", status: "conflict", detail: "Existing version has different contents" }] });
  await user.type(screen.getByRole("textbox", { name: "Pack release" }), "/source/release.efpack");
  await user.click(screen.getByRole("button", { name: "Review packs" }));
  await screen.findByRole("heading", { name: "Review import" });
  expect(screen.queryByRole("button", { name: "Validate prepared scenario" })).toBeNull();
  expect((screen.getByRole("button", { name: "Confirm import" }) as HTMLButtonElement).disabled).toBe(true);
  await user.keyboard("{Escape}");
  await waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(request.mock.calls.some(([path]) => path.endsWith("/commit"))).toBe(false);
});

test("native scenario browse requests only the YAML picker", async () => {
  window.__TAURI_INTERNALS__ = {} as Window["__TAURI_INTERNALS__"];
  vi.mocked(invoke).mockResolvedValue("/source/selected.yaml");
  const { user } = fixture();
  await selectImport(user);
  await user.click(screen.getByRole("button", { name: "Browse…" }));
  expect(invoke).toHaveBeenCalledWith("choose_import_file", { kind: "scenario" });
  expect((screen.getByRole("textbox", { name: "Scenario YAML" }) as HTMLInputElement).value).toBe("/source/selected.yaml");
});

test("dependency panel provides explicit refresh and missing-pack recovery", async () => {
  const request = vi.fn(async () => ({}));
  const onChanged = vi.fn(async () => undefined);
  const onImport = vi.fn();
  render(<DependencyPanel itemId="scenario" api={{ request } as unknown as StudioApi} health={{ ready: false, fingerprint: "hash", rows: review.rows, changed_at: 0 }} onChanged={onChanged} onImport={onImport} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Refresh dependencies" }));
  expect(request).toHaveBeenCalledWith("/v1/scenarios/scenario/dependencies/refresh", "POST", undefined, 180000);
  expect(onChanged).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Import packs" }));
  expect(onImport).toHaveBeenCalled();
});
