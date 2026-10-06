import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { DeletePackDialog } from "../src/DeletePackDialog";
import { PackWorkflow } from "../src/PackWorkflow";
import type { CatalogItem, StudioApi } from "../src/api";

const item = { id: "pack", name: "office", version: "1.0.0", kind: "organization_pack", source_sha256: "source", pack_source: "workspace" } as CatalogItem;
const removable = { reference: "training:organization:office@1.0.0", revision: "a".repeat(64), files: 9, bytes: 900, removable: true, consumers: [], problems: [] };
afterEach(cleanup);

for (const kind of ["industry_pack", "organization_pack"] as const) {
  test(`${kind} validates exact identity and dependency closure before exporting`, async () => {
    const request = vi.fn(async () => ({ valid: true, reference: "training:organization:office@1.0.0", digest: "pack-digest", dependencies: ["training:industry:sector@2.0.0"], exports: { persona_catalog: ["office-user"] } }));
    const onExport = vi.fn();
    render(<PackWorkflow item={{ ...item, kind }} api={{ request } as unknown as StudioApi} onPrepare={vi.fn()} onExport={onExport} />);
    expect(screen.getByRole("button", { name: "Export release…" })).toBeDisabled();
    await screen.findByText("training:industry:sector@2.0.0");
    expect(screen.getByText("persona: 1")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Export release…" }));
    expect(onExport).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Validate pack" }));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
  });
}

test("invalid packs keep export disabled and prepare a repair without sending a turn", async () => {
  const onPrepare = vi.fn(async () => undefined);
  const request = vi.fn(async () => ({ valid: false, error: "Missing locked dependency" }));
  render(<PackWorkflow item={item} api={{ request } as unknown as StudioApi} onPrepare={onPrepare} onExport={vi.fn()} />);
  await screen.findByText("Missing locked dependency");
  expect(screen.getByRole("button", { name: "Export release…" })).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: "Fix in chat" }));
  expect(onPrepare).toHaveBeenCalledWith(expect.stringContaining("new version before editing"));
  expect(request).toHaveBeenCalledTimes(1);
});

test("deletion requires a reviewed exact version and only runs after confirmation", async () => {
  const request = vi.fn(async (_path: string, method?: string) => method === "POST" ? { recovery_path: "/workspace/.eforge/deleted-packs/recovery" } : removable);
  const onDeleted = vi.fn(async () => undefined);
  render(<DeletePackDialog item={item} api={{ request } as unknown as StudioApi} onClose={vi.fn()} onDeleted={onDeleted} />);
  await screen.findByText(removable.reference);
  expect(request).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/Codex histories/)).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Delete version" }));
  await waitFor(() => expect(onDeleted).toHaveBeenCalledWith({ recovery_path: "/workspace/.eforge/deleted-packs/recovery" }));
  expect(request).toHaveBeenCalledWith("/v1/packs/pack/delete", "POST", { revision: removable.revision });
});

test("used packs show consumers and block deletion; refreshed reviews can clear them", async () => {
  const request = vi.fn().mockResolvedValueOnce({ ...removable, removable: false, consumers: ["Scenario: training"] }).mockResolvedValue(removable);
  render(<DeletePackDialog item={item} api={{ request } as unknown as StudioApi} onClose={vi.fn()} onDeleted={vi.fn()} />);
  await screen.findByText("Scenario: training");
  expect(screen.getByRole("button", { name: "Delete version" })).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: "Refresh review" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Delete version" })).toBeEnabled());
  expect(screen.queryByText("Scenario: training")).not.toBeInTheDocument();
});

test("stale review rejection requires a new review before retry", async () => {
  const request = vi.fn(async (_path: string, method?: string) => {
    if (method === "POST") throw new Error("Pack files or consumers changed. Review deletion again");
    return removable;
  });
  render(<DeletePackDialog item={item} api={{ request } as unknown as StudioApi} onClose={vi.fn()} onDeleted={vi.fn()} />);
  await screen.findByText(removable.reference);
  await userEvent.click(screen.getByRole("button", { name: "Delete version" }));
  await screen.findByRole("alert");
  expect(screen.getByRole("button", { name: "Delete version" })).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: "Refresh review" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Delete version" })).toBeEnabled());
});
