import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { ArtifactLifecycle } from "../src/ArtifactLifecycle";
import type { CatalogItem, StudioApi } from "../src/api";

afterEach(() => cleanup());
const item = { id: "draft", kind: "scenario", name: "test", path: "/workspace/scenario.yaml", version: "", source_sha256: "snapshot" } as CatalogItem;
const lifecycle = { status: "draft", draft_id: "885e4e69-02ac-4916-8c3d-bd1a85a7d168", parents: [], release_notes: "Original note" };

test("compact lifecycle controls delegate metadata editing to Properties", async () => {
  fixture();
  await screen.findByRole("button", { name: "Publish locally…" });
  expect(screen.queryByRole("textbox", { name: "Artifact display name" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Save display name" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Suggest display name with AI" })).toBeNull();
});
function fixture(metadata: unknown = lifecycle, upgrade = false, findings: unknown[] = []) {
  const request = vi.fn(async (_path: string, method?: string) => method === "POST" ? { path: "/workspace/release/source/scenario.yaml", findings } : { lifecycle: metadata, digest: "captured-digest", upgrade_available: upgrade, versions: [] });
  const onChanged = vi.fn(async () => undefined);
  const onOpen = vi.fn(async (_path: string) => undefined);
  const download = vi.fn(async () => ({ status: "browser" }));
  render(<ArtifactLifecycle item={item} api={{ request, download } as unknown as StudioApi} onChanged={onChanged} onOpen={onOpen} />);
  return { request, download, onChanged, onOpen, user: userEvent.setup() };
}

test("publication waits for a current review before enabling confirmation", async () => {
  let finishReview: ((value: object) => void) | undefined;
  let reads = 0;
  const request = vi.fn(async (_path: string, method?: string) => {
    if (method === "POST") return { path: "/release" };
    if (++reads === 2) return new Promise<object>((resolve) => { finishReview = resolve; });
    return { lifecycle, digest: "before", versions: [] };
  });
  render(<ArtifactLifecycle item={item} api={{ request } as unknown as StudioApi} onChanged={async () => undefined} />);
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Publish locally…" });
  await user.click(screen.getByRole("button", { name: "Publish locally…" }));
  const dialog = screen.getByRole("dialog", { name: "Publish local release" });
  expect(within(dialog).getByText("Reading the current draft…")).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Reviewing…" })).toBeDisabled();
  expect(request.mock.calls.some(([, method]) => method === "POST")).toBe(false);
  await act(async () => { finishReview!({ lifecycle, digest: "after", versions: [], suggested_version: "1.0.1" }); });
  expect(within(dialog).getByRole("button", { name: "Publish locally" })).toBeEnabled();
  expect(within(dialog).getByRole("textbox", { name: "Release version" })).toHaveValue("1.0.1");
  await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
  expect(request.mock.calls.some(([, method]) => method === "POST")).toBe(false);
});

test("later edits invalidate publication until the user refreshes and confirms again", async () => {
  let digest = "reviewed-before-dialog";
  const request = vi.fn(async (_path: string, method?: string, body?: unknown) => {
    if (method === "POST") {
      if ((body as { expected_digest: string }).expected_digest !== digest) throw new Error("source changed after review; inspect it again");
      return { path: "/workspace/release" };
    }
    return { lifecycle, digest, versions: [], suggested_version: "1.0.1" };
  });
  const api = { request } as unknown as StudioApi;
  const onOpen = vi.fn(async (_path: string) => undefined);
  const view = (source_sha256 = item.source_sha256) => <ArtifactLifecycle item={{ ...item, source_sha256 }} api={api} onOpen={onOpen} onChanged={async () => undefined} />;
  const rendered = render(view());
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Publish locally…" }));
  const dialog = screen.getByRole("dialog", { name: "Publish local release" });
  await waitFor(() => expect(within(dialog).getByRole("button", { name: "Publish locally" })).toBeEnabled());
  const version = within(dialog).getByRole("textbox", { name: "Release version" });
  await user.clear(version); await user.type(version, "1.1.0");
  digest = "edited-after-dialog";
  rendered.rerender(view("changed-manifest"));
  await waitFor(() => expect(request.mock.calls.filter(([, method]) => method !== "POST")).toHaveLength(3));
  await user.click(within(dialog).getByRole("button", { name: "Publish locally" }));
  expect(await within(dialog).findByRole("alert")).toHaveTextContent("source changed after review");
  expect(within(dialog).getByRole("button", { name: "Publish locally" })).toBeDisabled();
  expect(onOpen).not.toHaveBeenCalled();
  expect(request.mock.calls.filter(([, method]) => method === "POST")).toHaveLength(1);
  await user.click(within(dialog).getByRole("button", { name: "Refresh review" }));
  await waitFor(() => expect(within(dialog).getByRole("button", { name: "Publish locally" })).toBeEnabled());
  expect(version).toHaveValue("1.1.0");
  expect(request.mock.calls.filter(([, method]) => method === "POST")).toHaveLength(1);
  await user.click(within(dialog).getByRole("button", { name: "Publish locally" }));
  expect(request).toHaveBeenCalledWith("/v1/items/draft/lifecycle", "POST", {
    action: "publish", expected_digest: "edited-after-dialog", version: "1.1.0", accept_warnings: false,
  }, 180000);
  await waitFor(() => expect(onOpen).toHaveBeenCalledWith("/workspace/release"));
});

test("a failed current review cannot publish until a successful explicit refresh", async () => {
  let reads = 0;
  const request = vi.fn(async (_path: string, method?: string) => {
    if (method === "POST") return { path: "/release" };
    if (++reads === 2) throw new Error("Draft inspection unavailable");
    return { lifecycle, digest: "reviewed", versions: [] };
  });
  render(<ArtifactLifecycle item={item} api={{ request } as unknown as StudioApi} onChanged={async () => undefined} />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Publish locally…" }));
  const dialog = screen.getByRole("dialog", { name: "Publish local release" });
  expect(await within(dialog).findByRole("alert")).toHaveTextContent("Draft inspection unavailable");
  expect(within(dialog).getByRole("button", { name: "Publish locally" })).toBeDisabled();
  await user.click(within(dialog).getByRole("button", { name: "Refresh review" }));
  await waitFor(() => expect(within(dialog).getByRole("button", { name: "Publish locally" })).toBeEnabled());
  expect(request.mock.calls.some(([, method]) => method === "POST")).toBe(false);
});

test("publication is explicit and no release number is assigned while editing", async () => {
  const { request, user, onOpen } = fixture();
  await screen.findByRole("button", { name: "Publish locally…" });
  expect(screen.queryByRole("button", { name: "Upgrade to latest schema" })).toBeNull();
  await user.click(screen.getByRole("button", { name: "Publish locally…" }));
  expect(screen.getByRole("textbox", { name: "Release version" })).toHaveValue("");
  await user.type(screen.getByRole("textbox", { name: "Release version" }), "2.0.0");
  await user.click(screen.getByRole("button", { name: "Publish locally" }));
  expect(request).toHaveBeenCalledWith("/v1/items/draft/lifecycle", "POST", { action: "publish", version: "2.0.0", accept_warnings: false, expected_digest: "captured-digest" }, 180000);
  await waitFor(() => expect(onOpen).toHaveBeenCalledWith("/workspace/release/source/scenario.yaml"));
});

test("published artifacts expose export and independent drafts, and legacy upgrades are conditional", async () => {
  const { user, download } = fixture({ status: "published", publisher: "test", version: "1.0.0", parents: [], release_notes: "Immutable note" });
  await screen.findByRole("button", { name: "Export release…" });
  expect(screen.queryByRole("textbox", { name: "Release notes" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Publish locally…" })).toBeNull();
  await user.click(screen.getByRole("button", { name: "Export release…" }));
  expect(download).toHaveBeenCalled();
  cleanup();
  const legacy = fixture(null, true);
  await legacy.user.click(await screen.findByRole("button", { name: "Upgrade to latest schema" }));
  expect(legacy.request).toHaveBeenCalledWith("/v1/items/draft/lifecycle", "POST", { action: "upgrade", expected_digest: "captured-digest" }, 180000);
});

test("upgrades report repairable validation findings", async () => {
  const { user, onOpen } = fixture(null, true, [{ severity: "error", message: "Missing environment users" }]);
  await user.click(await screen.findByRole("button", { name: "Upgrade to latest schema" }));
  expect(await screen.findByText("error: Missing environment users")).toBeVisible();
  expect(onOpen).toHaveBeenCalledWith("/workspace/release/source/scenario.yaml");
});

for (const kind of ["scenario", "industry_pack", "organization_pack"] as const) {
  test(`${kind} publication reviews asset edits even when the entrypoint hash stays unchanged`, async () => {
    let digest = "before-asset-edit";
    const request = vi.fn(async (_path: string, method?: string, body?: unknown) => {
      if (method === "POST") {
        expect(body).toEqual(expect.objectContaining({ expected_digest: digest }));
        return { path: "/workspace/release/source/pack.yaml" };
      }
      return { lifecycle, digest, suggested_version: "1.0.1", versions: [] };
    });
    const onOpen = vi.fn(async (_path: string) => undefined);
    render(<ArtifactLifecycle item={{ ...item, kind }} api={{ request } as unknown as StudioApi} onChanged={async () => undefined} onOpen={onOpen} />);
    const user = userEvent.setup();
    await screen.findByRole("button", { name: "Publish locally…" });
    digest = "after-asset-edit";
    await user.click(screen.getByRole("button", { name: "Publish locally…" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Publish locally" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Publish locally" }));
    expect(request).toHaveBeenCalledWith("/v1/items/draft/lifecycle", "POST", {
      action: "publish", expected_digest: "after-asset-edit", version: "1.0.1", accept_warnings: false,
    }, 180000);
    await waitFor(() => expect(onOpen).toHaveBeenCalledWith("/workspace/release/source/pack.yaml"));
  });
}

