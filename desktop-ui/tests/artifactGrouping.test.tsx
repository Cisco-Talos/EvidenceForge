import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { Tooltip } from "radix-ui";
import type { CatalogItem, StudioApi, StudioSnapshot } from "../src/api";
import { artifactGroup, latestPublishedItems, type ArtifactGroups } from "../src/artifactGrouping";
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

function scenarios(items: CatalogItem[], artifact_groups = groups, expandedFamilies: string[] = []) {
  const snapshot = {
    settings: { workspace: "/workspace", output_parents: {} }, jobs: [], projects: [], conversations: [],
    validations: {}, dependencies: {}, forecasts: {}, artifact_groups,
  } as unknown as StudioSnapshot;
  return render(<Tooltip.Provider><ScenarioLibrary items={items} drafts={[]} snapshot={snapshot} api={{} as StudioApi} sort="name"
    onSort={vi.fn()} expandedFamilies={expandedFamilies} onToggleFamily={vi.fn()} dropTargetId={null}
    onProjectDragOver={vi.fn()} onProjectDragLeave={vi.fn()} onProjectDrop={vi.fn()}
    onOpen={vi.fn()} onOpenDraft={vi.fn()} onClone={vi.fn()} onExport={vi.fn()}
    onUnavailableExport={vi.fn()} onHide={vi.fn()} onDelete={vi.fn()} onMove={vi.fn()}
    onMoveDraft={vi.fn()} onNewProject={vi.fn()} onRenameDraft={vi.fn()}
    onDeleteDraft={vi.fn()} onDragStart={vi.fn()} onDraftDragStart={vi.fn()} onDragEnd={vi.fn()} /></Tooltip.Provider>);
}

test("scenario lineage collapses originals and anonymous drafts into one expandable row", () => {
  const view = scenarios(members);
  expect(document.querySelectorAll(".scenario-row")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Show 2 other versions of Test_scenario_1" })).toHaveAttribute("aria-expanded", "false");
  expect(screen.queryByRole("button", { name: "Open scenario Maple Office - PowerShell Discovery" })).toBeNull();
  view.unmount();
  scenarios(members, groups, ["shared-family"]);
  expect(document.querySelectorAll(".scenario-row")).toHaveLength(3);
  expect(document.querySelectorAll(".scenario-row.family-member")).toHaveLength(2);
  expect(screen.getByRole("button", { name: "Open scenario Maple Office - PowerShell Discovery" })).toBeInTheDocument();
  expect(document.querySelector(".artifact-identity-heading")).toBeNull();
  expect(members[0].publisher).toBe("");
  expect(members[1].publisher).toBe("");
});

test("filtered scenario lists retain the family from the complete workspace ancestry", () => {
  scenarios(members.slice(1), groups, ["shared-family"]);
  expect(document.querySelectorAll(".scenario-row")).toHaveLength(2);
  expect(screen.getByRole("button", { name: "Hide 1 other version of A Published Title" })).toHaveAttribute("aria-expanded", "true");
});

test("different publishers and unrelated anonymous identifiers remain separate", () => {
  expect(artifactGroup(item("one")).key).not.toBe(artifactGroup(item("two")).key);
  expect(artifactGroup(item("one", "team")).key).not.toBe(artifactGroup(item("two", "other")).key);
  const fork = item("fork", "other");
  scenarios([...members, fork], { ...groups, fork: { key: "fork-family", publisher: "other", name: fork.name } });
  expect(document.querySelectorAll(".scenario-row")).toHaveLength(2);
  expect(document.querySelectorAll(".family-toggle")).toHaveLength(1);
});

test("pack lists use the same ancestry families and keep each exact version available when expanded", () => {
  const packs = members.slice(1).map((member) => ({ ...member, kind: "organization_pack", pack_source: "workspace" } as CatalogItem));
  render(<PackLibrary items={packs} artifactGroups={groups} drafts={[]} projects={[]} busy={false} sort="name" onSort={vi.fn()}
    expandedFamilies={["shared-family"]} onToggleFamily={vi.fn()} dropTargetId={null} onProjectDragOver={vi.fn()} onProjectDragLeave={vi.fn()} onProjectDrop={vi.fn()} onOpen={vi.fn()}
    onOpenDraft={vi.fn()} onClone={vi.fn()} onExport={vi.fn()}
    onHide={vi.fn()} onMove={vi.fn()} onMoveDraft={vi.fn()} onDelete={vi.fn()}
    onNewProject={vi.fn()} onDeleteDraft={vi.fn()} onDragStart={vi.fn()} onDraftDragStart={vi.fn()} onDragEnd={vi.fn()} />);
  expect([...document.querySelectorAll("[data-artifact-identity]")].map((row) => row.getAttribute("data-artifact-identity"))).toEqual(["davidjbianco/Test_scenario_1", "davidjbianco/Test_scenario_1"]);
  expect(screen.getByRole("button", { name: "Open A Published Title 1.0.0" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Open Maple Office - PowerShell Discovery" })).toBeInTheDocument();
});

test("families headline the newest published release, then legacy versions, then drafts", async () => {
  const { artifactFamilies } = await import("../src/artifactGrouping");
  const old = { ...item("old", "team"), version: "1.0.9" };
  const current = { ...item("current", "team"), version: "1.0.10" };
  const draft = item("active", "team");
  const legacy = { ...item("legacy", "team"), version: "9.0.0" };
  const metadata: ArtifactGroups = {
    old: { key: "team", name: old.name, publisher: "team", published_version: "1.0.9" },
    current: { key: "team", name: current.name, publisher: "team", published_version: "1.0.10" },
    active: { key: "team", name: draft.name, publisher: "team", published_version: null },
    legacy: { key: "team", name: legacy.name, publisher: "team", published_version: null },
  };
  const [family] = artifactFamilies([old, draft, legacy, current], metadata);
  expect(family.primary.id).toBe("current");
  expect(family.others.map((entry) => entry.id)).toEqual(["active", "old", "legacy"]);
  const [bundled] = artifactFamilies([{ ...item("a", "team"), version: "1.0.0" }, { ...item("b", "team"), version: "1.1.0" }], {});
  expect(bundled.primary.id).toBe("b");
});

test("latest releases use numeric versions while keeping active drafts, legacy files and publisher forks", () => {
  const old = { ...item("old", "team"), version: "1.0.9" };
  const current = { ...item("current", "team"), version: "1.0.10" };
  const fork = { ...item("fork", "other"), version: "1.0.1" };
  const draft = item("active", "team");
  const legacy = { ...item("legacy", "team"), version: "9.0.0" };
  const metadata: ArtifactGroups = {
    old: { key: "team", name: old.name, publisher: "team", published_version: "1.0.9" },
    current: { key: "team", name: current.name, publisher: "team", published_version: "1.0.10" },
    fork: { key: "other", name: fork.name, publisher: "other", published_version: "1.0.1" },
    active: { key: "team", name: draft.name, publisher: "team", published_version: null },
    legacy: { key: "team", name: legacy.name, publisher: "team", published_version: null },
  };
  expect(latestPublishedItems([old, current, fork, draft, legacy], metadata).map((entry) => entry.id))
    .toEqual(["current", "fork", "active", "legacy"]);
  expect(latestPublishedItems([old, current], {}).map((entry) => entry.id)).toEqual(["old", "current"]);
});
