import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, expect, test, vi } from "vitest";
import type { ImportedBundle, StudioApi, StudioJob } from "../src/api";
import { ImportedBundleRow } from "../src/BundleLibrary";
import { JobCard } from "../src/components";

afterEach(cleanup);

const properties = { path: "/bundle", complete: true, size_bytes: 4096, data_bytes: 2048, data_files: 5, scenario: "Captured scenario", evidenceforge_version: "2.1.2", generation_seed: 42, formats: ["zeek_conn"], log_types: ["zeek_conn"], selected_packs: [], artifact: {}, overrides: {}, findings: [] };
const job: StudioJob = { id: "run", kind: "generation", status: "completed", status_message: "", can_resume: false, output_root: "/bundle", submitted_at: 1 };
const bundle: ImportedBundle = { id: "run", root: "/bundle", workspace: "/workspace", scenario_name: "Captured scenario", created_at: 1, size_bytes: 4096, manifest_sha256: "manifest" };

test.each([
  ["Studio", false, false], ["imported", true, false],
  ["Studio keyboard", false, true], ["imported keyboard", true, true],
] as const)("%s bundle menu opens every Properties section without expanding the row", async (_name, imported, keyboard) => {
  const request = vi.fn(async () => properties);
  const api = { request } as unknown as StudioApi;
  const user = userEvent.setup();
  const { container } = render(<Tooltip.Provider>{imported
    ? <ImportedBundleRow bundle={bundle} api={api} onError={vi.fn()} onChanged={vi.fn()} />
    : <JobCard job={job} api={api} onError={vi.fn()} onChanged={vi.fn()} />
  }</Tooltip.Provider>);
  const row = container.querySelector("details")!;
  const options = screen.getByRole("button", { name: "Bundle options for run" });
  expect(options.closest("summary")).toBe(row.querySelector("summary"));
  expect(row.open).toBe(false);
  if (keyboard) {
    options.focus();
    await user.keyboard("{Enter}{ArrowDown}{Enter}");
  } else {
    await user.click(options);
    await user.click(await screen.findByRole("menuitem", { name: "Properties…" }));
  }
  expect(await screen.findByRole("heading", { name: "Captured scenario" })).toBeVisible();
  expect(row.open).toBe(false);
  expect(request).toHaveBeenCalledWith(`/v1/${imported ? "bundles" : "jobs"}/run/properties`);
  await user.click(screen.getByRole("button", { name: "Captured inputs" }));
  expect(screen.getByText("No authored release identity recorded")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Technical details" }));
  expect(screen.getByText("2.0 KB · 5 files")).toBeVisible();
  expect(screen.getByText("Zeek · conn")).toBeVisible();
  expect(screen.getByText("EvidenceForge 2.1.2")).toBeVisible();
  expect(screen.getByText("42")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "General" }));
  expect(screen.getByRole("dialog")).toHaveTextContent("Completed");
  await user.click(screen.getByRole("button", { name: "Close properties" }));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(row.open).toBe(false);
});
