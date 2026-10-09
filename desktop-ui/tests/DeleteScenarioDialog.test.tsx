import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { DeleteScenarioDialog } from "../src/DeleteScenarioDialog";
import type { CatalogItem, StudioApi } from "../src/api";

afterEach(() => cleanup());
const item = { id: "case", name: "Case", kind: "scenario" } as CatalogItem;
const review = { source: "/workspace/scenarios/case/scenario.yaml", target: "/workspace/scenarios/case/scenario.yaml", revision: "a".repeat(64), files: 1, bytes: 100, whole_artifact: false, consumers: [], problems: [], removable: true };

test("removal is reviewed and Cancel never removes files", async () => {
  const request = vi.fn(async () => review);
  const close = vi.fn();
  render(<DeleteScenarioDialog item={item} api={{ request } as unknown as StudioApi} onClose={close} onDeleted={vi.fn()} />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Delete scenario" })).toBeEnabled());
  expect(screen.getByText(/Only the selected scenario YAML/)).toBeTruthy();
  await userEvent.setup().click(screen.getByRole("button", { name: "Cancel" }));
  expect(close).toHaveBeenCalledOnce();
  expect(request).toHaveBeenCalledExactlyOnceWith("/v1/scenarios/case/deletion");
});

test("a stale review requires refresh before another delete attempt", async () => {
  const result = { deleted_path: review.target };
  const request = vi.fn().mockResolvedValueOnce(review).mockRejectedValueOnce(new Error("Scenario changed. Review deletion again"))
    .mockResolvedValueOnce({ ...review, revision: "b".repeat(64), whole_artifact: true }).mockResolvedValueOnce(result);
  const deleted = vi.fn(async () => undefined);
  const user = userEvent.setup();
  render(<DeleteScenarioDialog item={item} api={{ request } as unknown as StudioApi} onClose={vi.fn()} onDeleted={deleted} />);
  const button = screen.getByRole("button", { name: "Delete scenario" });
  await waitFor(() => expect(button).toBeEnabled());
  await user.click(button);
  expect(screen.getByRole("alert").textContent).toContain("Review deletion again");
  expect(button).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Refresh review" }));
  await waitFor(() => expect(button).toBeEnabled());
  expect(screen.getByText(/including its source material and frozen inputs/)).toBeTruthy();
  await user.click(button);
  expect(request).toHaveBeenLastCalledWith("/v1/scenarios/case/delete", "POST", { revision: "b".repeat(64), include_files: false });
  expect(deleted).toHaveBeenCalledExactlyOnceWith(result);
});

test("included scenarios and authoring problems block deletion", async () => {
  const request = vi.fn(async () => ({ ...review, consumers: ["/workspace/scenarios/consumer.yaml"], problems: ["Wait for active authoring turns"], removable: false }));
  render(<DeleteScenarioDialog item={item} api={{ request } as unknown as StudioApi} onClose={vi.fn()} onDeleted={vi.fn()} />);
  await screen.findByText("/workspace/scenarios/consumer.yaml");
  expect(screen.getByText("Wait for active authoring turns")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Delete scenario" })).toBeDisabled();
});

test("all-files choice fetches a separate review and explicitly confirms its scope", async () => {
  const request = vi.fn(async (path: string, method?: string) => method === "POST" ? { deleted_path: "/workspace/scenarios/case" } : { ...review, revision: path.includes("include_files") ? "b".repeat(64) : review.revision, run_count: 2, run_paths: ["/workspace/runs/one", "/workspace/runs/two"] });
  const user = userEvent.setup();
  render(<DeleteScenarioDialog item={item} api={{ request } as unknown as StudioApi} onClose={vi.fn()} onDeleted={vi.fn(async () => undefined)} />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Delete scenario" })).toBeEnabled());
  expect(screen.getByText(/This cannot be undone/)).toBeVisible();
  const checkbox = screen.getByRole("checkbox", { name: /Also delete/ });
  expect(checkbox).not.toBeChecked();
  await user.click(checkbox);
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/scenarios/case/deletion?include_files=true"));
  expect(screen.getByText(/2 associated runs will be permanently deleted/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Delete scenario" }));
  expect(request).toHaveBeenLastCalledWith("/v1/scenarios/case/delete", "POST", { revision: "b".repeat(64), include_files: true });
});
