import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { currentPrediction, ResourceForecastPanel } from "../src/ResourceForecastPanel";
import type { CatalogItem, PredictionRecord, StudioApi, StudioSnapshot } from "../src/api";

const item = { id: "scenario", source_sha256: "sha" } as CatalogItem;
const range = (size: number) => ({ lower_bytes: size / 2, expected_bytes: size, upper_bytes: size * 2 });
const record: PredictionRecord = { source_sha256: "sha", dependency_fingerprint: "deps", input_fingerprint: "key", completed_at: 123,
  result: { available: true, destination: "/workspace/runs", checkpoint_hours: 24, forecast: {
    calibration_version: 5, calibration_label: "Fixture model", memory: range(1024 ** 2), final_output: range(2 * 1024 ** 2), disk: range(8 * 1024 ** 2), checkpoint_workspace: range(3 * 1024 ** 2),
    snapshot: { total_memory_bytes: 16 * 1024 ** 3, available_memory_bytes: 4 * 1024 ** 3, free_swap_bytes: 0, free_disk_bytes: 32 * 1024 ** 3, disk_path: "/workspace" }, pressures: [{ resource: "disk", level: "high", projected_bytes: 8 * 1024 ** 2, usable_bytes: 9 * 1024 ** 2, ratio: .9 }],
  } },
};
const snapshot = { settings: { workspace: "/workspace", output_parents: {}, checkpoint_hours: 24 }, dependencies: { scenario: { fingerprint: "deps" } }, forecasts: { scenario: record } } as unknown as StudioSnapshot;
afterEach(() => cleanup());

test("current predictions require matching source, dependencies, output parent and checkpoint interval", () => {
  expect(currentPrediction(item, snapshot)).toBe(record);
  expect(currentPrediction({ ...item, source_sha256: "edited" }, snapshot)).toBeUndefined();
  expect(currentPrediction(item, { ...snapshot, dependencies: { scenario: { ready: true, fingerprint: "pack-changed", rows: [] } } })).toBeUndefined();
  expect(currentPrediction(item, { ...snapshot, settings: { ...snapshot.settings, checkpoint_hours: 6 } })).toBeUndefined();
  expect(currentPrediction(item, { ...snapshot, settings: { ...snapshot.settings, output_parents: { "/workspace": "/other" } } })).toBeUndefined();
});

test("preflight shows estimates, ranges, pressure and expandable capacity details", async () => {
  const request = vi.fn(async () => record), onChanged = vi.fn(async () => undefined);
  render(<ResourceForecastPanel item={item} snapshot={snapshot} api={{ request } as unknown as StudioApi} onError={vi.fn()} onChanged={onChanged} />);
  expect(screen.getByText("2.0 MB")).toBeVisible();
  expect(screen.getByText("1.0 MB – 4.0 MB")).toBeVisible();
  expect(screen.getByText(/High disk pressure/)).toHaveClass("high");
  const user = userEvent.setup();
  await user.click(screen.getByText("Capacity and estimate details"));
  expect(screen.getByText(/Actual size and memory may differ/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Refresh resource forecast" }));
  await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
  expect(request).toHaveBeenCalledWith("/v1/scenarios/scenario/resources/predict", "POST", undefined, 180000);
});

test("stale projections disappear immediately and failures are informational", () => {
  const props = { item, snapshot, api: {} as StudioApi, onError: vi.fn(), onChanged: vi.fn(async () => undefined) };
  const { rerender } = render(<ResourceForecastPanel {...props} />);
  rerender(<ResourceForecastPanel {...props} item={{ ...item, source_sha256: "changed" }} />);
  expect(screen.queryByText("2.0 MB")).not.toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("Calculating an estimate");
  rerender(<ResourceForecastPanel {...props} snapshot={{ ...snapshot, forecasts: { scenario: { ...record, result: { ...record.result, available: false, forecast: null, error: "Missing exact pack" } } } }} />);
  expect(screen.getByRole("status")).toHaveTextContent("Estimate unavailable: Missing exact pack");
});
