import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, expect, test, vi } from "vitest";
import type { CatalogItem, StudioApi, StudioJob, StudioSnapshot } from "../src/api";
import { ScoringRuns } from "../src/ScoringRuns";

const item = { id: "scenario", source_sha256: "current", name: "Example" } as CatalogItem;
const snapshot = { dependencies: {} } as StudioSnapshot;
const run: StudioJob = { id: "first", kind: "generation", status: "completed", status_message: "", output_root: "/first", source_sha256: "current", submitted_at: 100, can_resume: false };
const second: StudioJob = { ...run, id: "second", submitted_at: 200 };
const evaluation: StudioJob = { ...run, id: "latest-score", kind: "evaluation", generation_id: "second", submitted_at: undefined, created_at: 300, scorecard: { overall_score: 92, acceptance_passed: false, total_records: 1000 } };
const detail = { scenario_name: "Example", evaluated_at: "2026-10-02T16:00:00Z", overall_score: 92, acceptance_passed: false, total_records: 1000, source_counts: { windows: 1000 }, pillars: [], acceptance_criteria: [], flags: [] };
function setup(jobs = [run, second, evaluation], request = vi.fn(async (_path: string) => detail), focusJobId: string | null = null) {
  const api = { request } as unknown as StudioApi;
  const onChanged = vi.fn(async () => undefined);
  const onError = vi.fn();
  const onNavigateJob = vi.fn();
  const props = { jobs, item, snapshot, api, onChanged, onError, onNavigateJob, focusJobId };
  const view = render(<Tooltip.Provider><ScoringRuns {...props} /></Tooltip.Provider>);
  return { ...view, props, request, onChanged, onError, onNavigateJob };
}
afterEach(() => cleanup());

test("scoring opens to run rows with scores and exact-run actions in submission order", async () => {
  const { container, request } = setup([second, evaluation, run, { ...run, id: "unfinished", status: "running", submitted_at: 400 }]);
  expect([...container.querySelectorAll(".score-run")].map((row) => row.id)).toEqual(["score-run-first", "score-run-second", "score-run-unfinished"]);
  expect(screen.queryByRole("combobox")).toBeNull();
  const first = screen.getByRole("region", { name: "Scoring run first" });
  const scored = screen.getByRole("region", { name: "Scoring run second" });
  expect(within(scored).getByText("92/100 · Failed")).toBeVisible();
  expect(within(scored).getByLabelText(/Evaluation: Failed acceptance/)).toHaveClass("state-error");
  expect(within(screen.getByRole("region", { name: "Scoring run unfinished" })).getByRole("button", { name: "Evaluate" })).toBeDisabled();
  await userEvent.setup().click(within(first).getByRole("button", { name: "Evaluate", exact: true }));
  expect(request).toHaveBeenCalledWith("/v1/jobs/evaluations", "POST", { generation_id: "first" });
  expect(within(first).getByRole("button", { name: "Run #first" })).toHaveAttribute("aria-expanded", "false");
});

test("keyboard expansion opens the scorecard directly and source navigation keeps its generation identity", async () => {
  const { request, onNavigateJob } = setup();
  const toggle = screen.getByRole("button", { name: "Run #second" });
  toggle.focus();
  await userEvent.setup().keyboard("{Enter}");
  expect(await screen.findByRole("region", { name: "Saved scorecard" })).toBeVisible();
  expect(request).toHaveBeenCalledWith("/v1/jobs/latest-score/scorecard");
  expect(screen.queryByRole("button", { name: "View scorecard", exact: true })).toBeNull();
  await userEvent.setup().click(screen.getByRole("button", { name: "Jump to generation #second" }));
  expect(onNavigateJob).toHaveBeenCalledWith(second);
});

test("focus can open a prior evaluation without replacing the latest outcome in the run header", async () => {
  const older: StudioJob = { ...evaluation, id: "older-score", created_at: 250, scorecard: { overall_score: 99, acceptance_passed: true } };
  const { request } = setup([second, evaluation, older], vi.fn(async () => detail), "older-score");
  await screen.findByRole("region", { name: "Saved scorecard" });
  expect(request).toHaveBeenCalledWith("/v1/jobs/older-score/scorecard");
  expect(screen.getByRole("button", { name: "Run #second" })).toHaveTextContent("92/100 · Failed");
  await userEvent.setup().click(screen.getByRole("button", { name: "Show latest evaluation" }));
  await waitFor(() => expect(request).toHaveBeenCalledWith("/v1/jobs/latest-score/scorecard"));
});

test.each(["queued", "running", "paused"])("an existing %s evaluation prevents another evaluation of that run", (status) => {
  setup([second, { ...evaluation, status, scorecard: undefined }]);
  const row = screen.getByRole("region", { name: "Scoring run second" });
  expect(within(row).getByRole("button", { name: status === "paused" ? "Evaluation paused" : "Evaluation in progress" })).toBeDisabled();
});

test("queuing one evaluation leaves other run actions available and recovers from a failed request", async () => {
  let reject!: (error: Error) => void;
  const request = vi.fn(() => new Promise<typeof detail>((_resolve, fail) => { reject = fail; }));
  const { onError } = setup([run, second], request);
  const user = userEvent.setup();
  const first = screen.getByRole("region", { name: "Scoring run first" });
  const other = screen.getByRole("region", { name: "Scoring run second" });
  await user.click(within(first).getByRole("button", { name: "Evaluate", exact: true }));
  await user.click(within(first).getByRole("button", { name: "Queuing…" }));
  expect(request).toHaveBeenCalledTimes(1);
  expect(within(other).getByRole("button", { name: "Evaluate" })).toBeEnabled();
  await act(async () => reject(new Error("Could not queue evaluation")));
  expect(onError).toHaveBeenCalledWith("Error: Could not queue evaluation");
  expect(within(first).getByRole("button", { name: "Evaluate" })).toBeEnabled();
});


test("an evaluation arriving after navigation opens its run without reopening a manually collapsed row", async () => {
  const { props, rerender, request } = setup([second], vi.fn(async () => detail), "latest-score");
  expect(screen.getByRole("button", { name: "Run #second" })).toHaveAttribute("aria-expanded", "false");
  rerender(<Tooltip.Provider><ScoringRuns {...props} jobs={[second, evaluation]} /></Tooltip.Provider>);
  await screen.findByRole("region", { name: "Saved scorecard" });
  expect(request).toHaveBeenCalledWith("/v1/jobs/latest-score/scorecard");
  await userEvent.setup().click(screen.getByRole("button", { name: "Run #second" }));
  rerender(<Tooltip.Provider><ScoringRuns {...props} jobs={[{ ...second }, { ...evaluation }]} /></Tooltip.Provider>);
  expect(screen.getByRole("button", { name: "Run #second" })).toHaveAttribute("aria-expanded", "false");
});


test("a repeated explicit navigation request reopens the same scorecard after manual collapse", async () => {
  const { props, rerender } = setup([second, evaluation], vi.fn(async () => detail), "latest-score");
  await screen.findByRole("region", { name: "Saved scorecard" });
  await userEvent.setup().click(screen.getByRole("button", { name: "Run #second" }));
  expect(screen.queryByRole("region", { name: "Saved scorecard" })).toBeNull();
  rerender(<Tooltip.Provider><ScoringRuns {...props} focusVersion={1} /></Tooltip.Provider>);
  expect(await screen.findByRole("region", { name: "Saved scorecard" })).toBeVisible();
});


test("a failed score remains red while unverified legacy inputs have a separate warning", async () => {
  const { props, rerender } = setup([second, { ...evaluation, scorecard: { overall_score: 96, acceptance_passed: false } }]);
  rerender(<Tooltip.Provider><ScoringRuns {...props} snapshot={{ dependencies: { scenario: { ready: true, fingerprint: "checked-later", changed_at: 300, rows: [] } } } as StudioSnapshot} /></Tooltip.Provider>);
  const row = screen.getByRole("region", { name: "Scoring run second" });
  expect(within(row).getByLabelText(/Evaluation: Failed acceptance · 96\/100/)).toHaveClass("state-error");
  expect(within(row).getByText("Inputs unverified")).toBeVisible();
  await userEvent.setup().click(within(row).getByRole("button", { name: "Run #second" }));
  expect(within(row).getByText(/a later dependency check cannot establish/)).toBeVisible();
  expect(within(row).queryByText(/dependencies have changed/)).toBeNull();
});
