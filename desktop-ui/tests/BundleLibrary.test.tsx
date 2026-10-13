import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "radix-ui";
import { afterEach, expect, test, vi } from "vitest";
import { BundleLibrary } from "../src/BundleLibrary";
import { groupBundles } from "../src/bundleGrouping";
import type { CapturedScenario, CatalogItem, StudioApi, StudioJob, StudioSnapshot } from "../src/api";

afterEach(cleanup);
const workspace = "/workspace";
const release = (id: string, version: string, publisher = "team") => ({ id, kind: "scenario", name: "test-1", path: `/workspace/scenarios/${publisher}/test-1/${version}/scenario.yaml`, publisher, version, project_id: null } as CatalogItem);
const source = (version: string): CapturedScenario => ({ name: "test-1", publisher: "team", version, status: "published" });
const run = (id: string, scenario: string, scenario_source?: CapturedScenario, submitted_at = 1) => ({ id, kind: "generation", status: "completed", output_root: `/runs/${id}`, scenario, scenario_source, submitted_at } as StudioJob);

function fixture(): StudioSnapshot {
  const old = release("old", "1.0.0");
  const current = release("current", "2.0.0");
  return {
    items: [old, current], projects: [],
    artifact_groups: { old: { key: "family", name: "test-1", publisher: "team", published_version: "1.0.0" }, current: { key: "family", name: "test-1", publisher: "team", published_version: "2.0.0" } },
    source_paths: { current: [current.path, "/drafts/previous/source/scenario.yaml"] },
    jobs: [run("latest", current.path, source("2.0.0"), 5), run("previous", old.path, source("1.0.0"), 3), run("draft-run", "/drafts/previous/source/scenario.yaml", { name: "test-1", status: "draft", draft_id: "previous" }, 2), run("source-run", "/retired/source/scenario.yaml", source("1.0.0"))],
    imported_bundles: [{ id: "cli", root: "/external/run", scenario_name: "test-1", scenario_source: source("1.0.0"), created_at: 4, size_bytes: 1024 }],
  } as StudioSnapshot;
}

function setup(snapshot = fixture()) {
  const request = vi.fn(async (path: string) => path === "/v1/jobs/bundle-sizes" ? { latest: 2048 } : { available: true, tail: "Saved generator log", log_path: "/runs/generation.log" });
  const onOpenScenario = vi.fn();
  const api = { request } as unknown as StudioApi;
  const view = render(<Tooltip.Provider><BundleLibrary snapshot={snapshot} api={api} onOpenScenario={onOpenScenario} onError={vi.fn()} onChanged={async () => undefined} /></Tooltip.Provider>);
  return { ...view, onOpenScenario, request };
}

test("versions, relocated draft runs and imports share one family with captured version labels", async () => {
  const { container } = setup();
  expect(container.querySelectorAll(".bundle-group")).toHaveLength(1);
  const group = container.querySelector<HTMLDetailsElement>(".bundle-group")!;
  expect(group.open).toBe(false);
  await userEvent.setup().click(group.querySelector("summary")!);
  const labels = [...group.querySelectorAll(".job-row .scenario-version")].map((node) => node.textContent);
  expect(labels).toEqual(["v2.0.0", "v1.0.0", "v1.0.0", "Draft", "v1.0.0"]);
  expect(screen.getByText("5 bundles")).toBeVisible();
  expect(container.querySelectorAll(".bundle-group > summary strong")[0]).toHaveTextContent("test-1");
  expect(container.querySelectorAll(".bundle-group > summary strong")[0]).not.toHaveTextContent("source");
  await userEvent.setup().type(screen.getByRole("textbox", { name: "Search bundles" }), "v2.0.0");
  expect(container.querySelectorAll(".job-list > .job-row")).toHaveLength(1);
});

test("bundle group menus contain navigation and disclosure actions and leave generation actions on each run", async () => {
  const { container } = setup();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Bundle group actions for test-1" }));
  expect(screen.getAllByRole("menuitem").map((item) => item.getAttribute("aria-label"))).toEqual(["Open latest run", "Expand all runs", "Collapse all runs", "Open scenario"]);
  expect(screen.getByRole("menuitem", { name: "Collapse all runs" })).toHaveAttribute("data-disabled");
  expect(screen.queryByRole("menuitem", { name: /Validate|Forecast|Generate|Publish|Delete scenario|New conversation/ })).toBeNull();
  await user.click(screen.getByRole("menuitem", { name: "Expand all runs" }));
  expect([...container.querySelectorAll<HTMLDetailsElement>(".job-list > .job-row")].every((row) => row.open)).toBe(true);
  const diagnostics = await screen.findAllByRole("region", { name: "Run diagnostics" });
  expect(diagnostics.length).toBe(4);
  expect(diagnostics.every((region) => within(region).queryByRole("button", { name: "View log" }) === null)).toBe(true);
  expect(screen.queryByRole("button", { name: /^Log actions/ })).toBeNull();
  await user.click(screen.getByRole("button", { name: "Bundle options for latest" }));
  await user.click(screen.getByRole("menuitem", { name: "View log", exact: true }));
  expect(container.querySelector(".bundle-group")).toHaveAttribute("open");
  expect(container.querySelector("#job-latest")).toHaveAttribute("open");
  expect(await screen.findByText("Saved generator log")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Bundle options for latest" }));
  await user.click(screen.getByRole("menuitem", { name: "Hide log", exact: true }));
  expect(screen.queryByText("Saved generator log")).toBeNull();
});

test("collapse all folds Studio and imported runs while keeping the group open, and is disabled for a closed list", async () => {
  const { container } = setup();
  const user = userEvent.setup();
  const group = container.querySelector<HTMLDetailsElement>(".bundle-group")!;
  const menu = screen.getByRole("button", { name: "Bundle group actions for test-1" });
  const runs = () => [...group.querySelectorAll<HTMLDetailsElement>(".job-list > .job-row")];

  await user.click(menu);
  await user.click(screen.getByRole("menuitem", { name: "Expand all runs" }));
  expect(group.open).toBe(true);
  expect(runs()).toHaveLength(5);
  expect(runs().every((row) => row.open)).toBe(true);

  await user.click(menu);
  expect(screen.getByRole("menuitem", { name: "Collapse all runs" })).not.toHaveAttribute("data-disabled");
  await user.click(screen.getByRole("menuitem", { name: "Collapse all runs" }));
  expect(group.open).toBe(true);
  expect(runs().every((row) => !row.open)).toBe(true);
  expect(screen.getByText("Run #latest")).toBeVisible();

  await user.click(group.querySelector("summary")!);
  expect(group.open).toBe(false);
  await user.click(menu);
  await waitFor(() => expect(screen.getByRole("menuitem", { name: "Collapse all runs" })).toHaveAttribute("data-disabled"));
  await user.keyboard("{Escape}");

  await user.click(group.querySelector("summary")!);
  await user.click(menu);
  await waitFor(() => expect(screen.getByRole("menuitem", { name: "Collapse all runs" })).not.toHaveAttribute("data-disabled"));
  await user.click(screen.getByRole("menuitem", { name: "Open latest run" }));
  expect(runs().map((row) => row.open)).toEqual([true, false, false, false, false]);
});

test("same-name scenarios from different publishers stay distinct, and retired source groups still have menus", async () => {
  const snapshot = fixture();
  const other = release("other", "1.0.0", "other");
  snapshot.items.push(other);
  snapshot.artifact_groups!.other = { key: "other-family", name: "test-1", publisher: "other", published_version: "1.0.0" };
  snapshot.jobs.push(run("other-run", other.path, { ...source("1.0.0"), publisher: "other" }));
  snapshot.jobs.push(run("retired", "/retired/source/scenario.yaml", { name: "retired-scenario", status: "legacy" }));
  const { container } = setup(snapshot);
  expect(container.querySelectorAll(".bundle-group")).toHaveLength(3);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Bundle group actions for retired-scenario" }));
  expect(screen.getByRole("menuitem", { name: "Open latest run" })).toBeVisible();
  expect(screen.getByRole("menuitem", { name: /Open scenario/ })).toHaveAttribute("data-disabled");
});

test("an unrelated anonymous draft never adopts a publisher only because its name matches", () => {
  const snapshot = fixture();
  snapshot.jobs.push(run("unrelated", "/unrelated/source/scenario.yaml", { name: "test-1", status: "draft", draft_id: "unrelated" }));
  expect(groupBundles(snapshot)).toHaveLength(2);
});
