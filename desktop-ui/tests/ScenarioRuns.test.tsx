import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, expect, test, vi } from "vitest";
import type { CatalogItem, ImportedBundle, StudioApi, StudioJob, StudioSnapshot } from "../src/api";
import { ScenarioRuns } from "../src/ScenarioRuns";

const item = { id: "scenario", source_sha256: "current", name: "Example" } as CatalogItem;
const snapshot = { dependencies: {} } as StudioSnapshot;
const run: StudioJob = { id: "first", kind: "generation", status: "completed", status_message: "", output_root: "/first", source_sha256: "current", submitted_at: 100, can_resume: false };
const second: StudioJob = { ...run, id: "second", submitted_at: 200 };
const evaluation: StudioJob = { ...run, id: "latest-score", kind: "evaluation", generation_id: "second", submitted_at: undefined, created_at: 300, scorecard: { overall_score: 92, acceptance_passed: false, total_records: 1000 } };
const detail = { scenario_name: "Example", evaluated_at: "2026-10-02T16:00:00Z", overall_score: 92, acceptance_passed: false, total_records: 1000, source_counts: { windows: 1000 }, pillars: [{ name: "Parseability", score: 90, sub_scores: [{ name: "Schema", score: 90, skipped: false, rating: "passed", details: "Valid records" }] }], acceptance_criteria: [], flags: [] };
function setup(jobs = [run, second, evaluation], request = vi.fn(async (_path: string) => detail), focusJobId: string | null = null, imports: ImportedBundle[] = []) {
  const api = { request, downloadBundle: vi.fn(async () => ({ status: "browser" })) } as unknown as StudioApi;
  const onChanged = vi.fn(async () => undefined);
  const onError = vi.fn();
  const props = { jobs, item, snapshot, imports, sizes: { first: 1024, second: 2097152 }, api, onChanged, onError, focusJobId, focusVersion: 0 };
  const view = render(<Tooltip.Provider><ScenarioRuns {...props} /></Tooltip.Provider>);
  return { ...view, props, request, onChanged, onError, api };
}
function row(id: string): HTMLDetailsElement { return document.getElementById(`workspace-run-${id}`) as HTMLDetailsElement; }
async function open(id: string) { await userEvent.setup().click(row(id).querySelector("summary")!); }
afterEach(() => cleanup());

test("runs directly list bundles and their scores in stable original submission order", async () => {
  const imported = { id: "import", root: "/external/bundle", created_at: 150, size_bytes: 1024 } as ImportedBundle;
  const { container, request, props, rerender } = setup([second, evaluation, run, { ...run, id: "unfinished", status: "running", submitted_at: 400 }], vi.fn(async () => detail), null, [imported]);
  expect([...container.querySelectorAll(".scenario-runs > .job-row")].map((entry) => entry.id)).toEqual(["workspace-run-unfinished", "workspace-run-second", "bundle-import", "workspace-run-first"]);
  expect(row("second").querySelector("summary")).toHaveTextContent("2.0 MB");
  expect(within(row("second")).getByText("92/100 · Failed · 1,000 records")).toBeVisible();
  expect(within(row("second")).getByLabelText(/Evaluation: Failed acceptance/)).toHaveClass("state-error");
  expect(request).not.toHaveBeenCalled();
  await open("unfinished");
  expect(within(row("unfinished")).getByRole("button", { name: "Evaluate" })).toBeDisabled();
  await open("first");
  await userEvent.setup().click(within(row("first")).getByRole("button", { name: "Evaluate" }));
  expect(request).toHaveBeenCalledWith("/v1/jobs/evaluations", "POST", { generation_id: "first" });
  rerender(<Tooltip.Provider><ScenarioRuns {...props} jobs={[{ ...second, started_at: 999 }, evaluation, { ...run, started_at: 1000 }]} /></Tooltip.Provider>);
  expect([...container.querySelectorAll(".workspace-run")].map((entry) => entry.id)).toEqual(["workspace-run-second", "workspace-run-first"]);
});

test("expanding a run opens its scorecard beside bundle actions without an intermediate picker", async () => {
  const { request } = setup();
  await open("second");
  expect(await screen.findByRole("region", { name: "Saved scorecard" })).toBeVisible();
  expect(request).toHaveBeenCalledWith("/v1/jobs/latest-score/scorecard");
  for (const name of ["View files", "Download ZIP", "Re-evaluate", "Delete"]) expect(within(row("second")).getByRole("button", { name })).toBeVisible();
  expect(screen.queryByRole("button", { name: "View scorecard", exact: true })).toBeNull();
  expect(screen.queryByRole("combobox")).toBeNull();
  expect(screen.getByText("Parseability")).toBeVisible();
  expect(screen.getByRole("button", { name: "View raw report" })).toBeVisible();
});

test("only the latest saved evaluation is shown and older links resolve to the same run", async () => {
  const older = { ...evaluation, id: "older-score", created_at: 250, scorecard: { overall_score: 99, acceptance_passed: true } };
  const { request } = setup([second, evaluation, older], vi.fn(async () => detail), "older-score");
  await screen.findByRole("region", { name: "Saved scorecard" });
  expect(request).toHaveBeenCalledWith("/v1/jobs/latest-score/scorecard");
  expect(request).not.toHaveBeenCalledWith("/v1/jobs/older-score/scorecard");
  expect(row("second").querySelector("summary")).toHaveTextContent("92/100 · Failed");
  expect(screen.queryByText(/Earlier evaluations/)).toBeNull();
});

test.each(["queued", "running", "paused"])("an existing %s evaluation prevents a duplicate while keeping the previous saved score visible", async (status) => {
  setup([second, evaluation, { ...evaluation, id: "new-attempt", created_at: 400, status, scorecard: undefined }]);
  await open("second");
  expect(within(row("second")).getByRole("button", { name: status === "paused" ? "Evaluation paused" : "Evaluation in progress" })).toBeDisabled();
  expect(await screen.findByRole("region", { name: "Saved scorecard" })).toBeVisible();
  expect(screen.getByText(/Previous saved score remains available/)).toBeVisible();
});

test("queuing one evaluation leaves other run actions available and recovers from a failed request", async () => {
  let reject!: (error: Error) => void;
  const request = vi.fn(() => new Promise<typeof detail>((_resolve, fail) => { reject = fail; }));
  const { onError } = setup([run, second], request);
  const user = userEvent.setup();
  await open("first"); await open("second");
  await user.click(within(row("first")).getByRole("button", { name: "Evaluate" }));
  await user.click(within(row("first")).getByRole("button", { name: "Queuing…" }));
  expect(request).toHaveBeenCalledTimes(1);
  expect(within(row("second")).getByRole("button", { name: "Evaluate" })).toBeEnabled();
  await act(async () => reject(new Error("Could not queue evaluation")));
  expect(onError).toHaveBeenCalledWith("Error: Could not queue evaluation");
  expect(within(row("first")).getByRole("button", { name: "Evaluate" })).toBeEnabled();
});

test("delayed evaluation navigation opens the exact run; updates respect manual collapse and explicit navigation reopens it", async () => {
  const { props, rerender, request } = setup([run, second], vi.fn(async () => detail), "latest-score");
  expect(row("second")).not.toHaveAttribute("open");
  rerender(<Tooltip.Provider><ScenarioRuns {...props} jobs={[run, second, evaluation]} /></Tooltip.Provider>);
  await screen.findByRole("region", { name: "Saved scorecard" });
  expect(request).toHaveBeenCalledWith("/v1/jobs/latest-score/scorecard");
  expect(row("first")).not.toHaveAttribute("open");
  await open("second");
  rerender(<Tooltip.Provider><ScenarioRuns {...props} jobs={[run, { ...second }, { ...evaluation }]} /></Tooltip.Provider>);
  expect(row("second")).not.toHaveAttribute("open");
  rerender(<Tooltip.Provider><ScenarioRuns {...props} jobs={[run, second, evaluation]} focusVersion={1} /></Tooltip.Provider>);
  await waitFor(() => expect(row("second")).toHaveAttribute("open"));
});

test("a new saved report replaces the scorecard inline and a failed retry preserves its predecessor", async () => {
  const { props, rerender, request } = setup([second, evaluation]);
  await open("second");
  await screen.findByRole("region", { name: "Saved scorecard" });
  const failed = { ...evaluation, id: "retry", status: "failed", created_at: 500, scorecard: undefined, status_message: "Evaluation stopped" };
  rerender(<Tooltip.Provider><ScenarioRuns {...props} jobs={[second, evaluation, failed]} /></Tooltip.Provider>);
  expect(screen.getByRole("region", { name: "Saved scorecard" })).toBeVisible();
  expect(request).not.toHaveBeenCalledWith("/v1/jobs/retry/scorecard");
  rerender(<Tooltip.Provider><ScenarioRuns {...props} jobs={[second, { ...evaluation, id: "replacement", created_at: 600 }]} /></Tooltip.Provider>);
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/jobs/replacement/scorecard"));
  expect(screen.queryByText(/Earlier evaluations/)).toBeNull();
});

test("a failed score remains red while unverified inputs have a separate warning", async () => {
  const { props, rerender } = setup([second, { ...evaluation, scorecard: { overall_score: 96, acceptance_passed: false } }]);
  rerender(<Tooltip.Provider><ScenarioRuns {...props} snapshot={{ dependencies: { scenario: { ready: true, fingerprint: "checked-later", changed_at: 300, rows: [] } } } as StudioSnapshot} /></Tooltip.Provider>);
  expect(within(row("second")).getByLabelText(/Evaluation: Failed acceptance · 96\/100/)).toHaveClass("state-error");
  expect(within(row("second")).getByText("Inputs unverified")).toBeVisible();
  await open("second");
  expect(within(row("second")).getByText(/a later dependency check cannot establish/)).toBeVisible();
  expect(within(row("second")).queryByText(/dependencies have changed/)).toBeNull();
});

test.each([
  { status: "running", can_resume: false, action: "Suspend", endpoint: "/v1/jobs/first/suspend", body: undefined },
  { status: "paused", can_resume: true, action: "Resume", endpoint: "/v1/jobs/resume", body: { generation_id: "first" } },
  { status: "stopped", can_resume: false, action: "Regenerate", endpoint: "/v1/jobs/first/regenerate", body: undefined },
])("$status runs retain their lifecycle actions", async ({ status, can_resume, action, endpoint, body }) => {
  const { request } = setup([{ ...run, status, can_resume }]);
  await open("first");
  await userEvent.setup().click(within(row("first")).getByRole("button", { name: action }));
  expect(request).toHaveBeenCalledWith(endpoint, "POST", ...(body ? [body] : []));
});

test("partial export, built-in viewing and confirmed bundle deletion operate on the selected run", async () => {
  const request = vi.fn(async (path: string) => path.endsWith("/files") ? { root: "/first", files: [], truncated: false } : detail);
  const { api } = setup([{ ...run, status: "stopped" }], request as ReturnType<typeof vi.fn<(_path: string) => Promise<typeof detail>>>);
  await open("first");
  const user = userEvent.setup();
  await user.click(within(row("first")).getByRole("button", { name: "Download partial ZIP" }));
  expect(api.downloadBundle).toHaveBeenCalledWith("first", "Example-partial-first.zip", expect.any(Function));
  await user.click(within(row("first")).getByRole("button", { name: "View files" }));
  expect(request).toHaveBeenCalledWith("/v1/jobs/first/files");
  await user.click(screen.getByRole("button", { name: "Close bundle files" }));
  await user.click(within(row("first")).getByRole("button", { name: "Delete" }));
  await user.click(screen.getByRole("menuitem", { name: /Delete bundle/ }));
  expect(request).not.toHaveBeenCalledWith("/v1/jobs/first/incomplete-bundle", "DELETE");
  await user.click(screen.getByRole("button", { name: "Delete bundle", exact: true }));
  expect(request).toHaveBeenCalledWith("/v1/jobs/first/incomplete-bundle", "DELETE");
});
