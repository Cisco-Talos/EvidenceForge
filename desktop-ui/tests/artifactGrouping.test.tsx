import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { Tooltip } from "radix-ui";
import type { CatalogItem, StudioApi, StudioSnapshot } from "../src/api";
import { artifactGroup, type ArtifactGroups } from "../src/artifactGrouping";
import { ScenarioLibrary } from "../src/ScenarioLibrary";
import { PackLibrary } from "../src/PackLibrary";

afterEach(cleanup);

const item = (id: string, publisher = "", display_name: string | null = null) => ({
  id, name: "Test_scenario_1", publisher, display_name, kind: "scenario",
  path: `/workspace/${id}/scenario.yaml`, workspace: "/workspace", description: "Test",
  version: id === "original" ? "2.0" : id === "release" ? "1.0.0" : "",
  modified_at: 0, project_id: null, hidden: false,
} as CatalogItem);

const members = [item("original"), item("draft", "", "Maple Office - PowerShell Discovery"), item("release", "davidjbianco", "A Published Title")];
const groups: ArtifactGroups = Object.fromEntries(members.map((member) => [member.id, {
  key: "shared-family", name: member.name, publisher: "davidjbianco",
}]));

function scenarios(items: CatalogItem[], artifact_groups = groups) {
  const snapshot = {
    settings: { workspace: "/workspace", output_parents: {} }, jobs: [], projects: [], conversations: [],
    validations: {}, dependencies: {}, forecasts: {}, artifact_groups,
  } as unknown as StudioSnapshot;
  return render(<Tooltip.Provider><ScenarioLibrary items={items} drafts={[]} snapshot={snapshot} api={{} as StudioApi} sort="name"
    expandedGroups={["ungrouped"]} onToggleGroup={vi.fn()} dropTargetId={null}
    onProjectDragOver={vi.fn()} onProjectDragLeave={vi.fn()} onProjectDrop={vi.fn()}
    onOpen={vi.fn()} onOpenDraft={vi.fn()} onClone={vi.fn()} onExport={vi.fn()}
    onUnavailableExport={vi.fn()} onHide={vi.fn()} onDelete={vi.fn()} onMove={vi.fn()}
    onMoveDraft={vi.fn()} onNewProject={vi.fn()} onRenameDraft={vi.fn()}
    onDeleteDraft={vi.fn()} onDragStart={vi.fn()} onDraftDragStart={vi.fn()} onDragEnd={vi.fn()} /></Tooltip.Provider>);
}

test("scenario lineage groups originals and anonymous drafts despite different display names", () => {
  scenarios(members);
  expect(screen.getAllByText("davidjbianco/Test_scenario_1 · drafts & releases")).toHaveLength(1);
  expect(document.querySelectorAll(".scenario-row")).toHaveLength(3);
  expect(document.querySelectorAll(".artifact-identity-heading")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Open scenario Maple Office - PowerShell Discovery" })).toBeInTheDocument();
  expect(members[0].publisher).toBe("");
  expect(members[1].publisher).toBe("");
});

test("filtered scenario lists retain the group from the complete workspace ancestry", () => {
  scenarios(members.slice(1));
  expect(screen.getByText("davidjbianco/Test_scenario_1 · drafts & releases")).toBeInTheDocument();
  expect(document.querySelectorAll(".scenario-row")).toHaveLength(2);
});

test("different publishers and unrelated anonymous identifiers remain separate", () => {
  expect(artifactGroup(item("one")).key).not.toBe(artifactGroup(item("two")).key);
  expect(artifactGroup(item("one", "team")).key).not.toBe(artifactGroup(item("two", "other")).key);
  const fork = item("fork", "other");
  scenarios([...members, fork], { ...groups, fork: { key: "fork-family", publisher: "other", name: fork.name } });
  expect(document.querySelectorAll(".artifact-identity-heading")).toHaveLength(2);
  expect(screen.getByText("other/Test_scenario_1")).toBeInTheDocument();
});

test("pack lists use the same ancestry grouping and keep each exact version available", () => {
  const packs = members.slice(1).map((member) => ({ ...member, kind: "organization_pack", pack_source: "workspace" } as CatalogItem));
  render(<PackLibrary items={packs} artifactGroups={groups} drafts={[]} projects={[]} busy={false}
    expandedGroups={["organization_pack"]} onToggleGroup={vi.fn()} onOpen={vi.fn()}
    onOpenDraft={vi.fn()} onNew={vi.fn()} onClone={vi.fn()} onExport={vi.fn()}
    onHide={vi.fn()} onMove={vi.fn()} onMoveDraft={vi.fn()} onDelete={vi.fn()}
    onNewProject={vi.fn()} onDeleteDraft={vi.fn()} onDragStart={vi.fn()} onDraftDragStart={vi.fn()} onDragEnd={vi.fn()} />);
  expect(screen.getByText("davidjbianco/Test_scenario_1 · drafts & releases")).toBeInTheDocument();
  expect([...document.querySelectorAll("[data-artifact-identity]")].map((row) => row.getAttribute("data-artifact-identity"))).toEqual(["davidjbianco/Test_scenario_1", "davidjbianco/Test_scenario_1"]);
  expect(screen.getByRole("button", { name: "Open A Published Title 1.0.0" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Open Maple Office - PowerShell Discovery" })).toBeInTheDocument();
});
