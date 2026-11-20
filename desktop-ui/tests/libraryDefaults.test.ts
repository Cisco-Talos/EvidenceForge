import { expect, test } from "vitest";
import { groupRows, libraryGroupKey, packSortOptions, scenarioSortOptions, sortLabels, sortRows } from "../src/LibraryTable";
import { defaultLibrarySort, emptyLibraryView } from "../src/useLibraryRecall";

test("libraries open grouped: scenarios by project and packs by publisher", () => {
  expect(defaultLibrarySort("scenarios")).toBe("project");
  expect(defaultLibrarySort("packs")).toBe("publisher");
  expect(emptyLibraryView.sort).toBe("project");
  expect(scenarioSortOptions.map((sort) => sortLabels[sort])).toEqual(["Name A–Z", "Recently updated", "Group by project"]);
  expect(packSortOptions.map((sort) => sortLabels[sort])).toEqual(["Name A–Z", "Recently updated", "Group by project", "Group by publisher"]);
});

test("publisher grouping orders groups by publisher name and keeps name order inside them", () => {
  // PackLibrary always supplies a publisher label, using "Unknown publisher" when none is recorded.
  const row = (id: string, name: string, publisher: string) => ({ id, name, publisher, updated: 0, project: "Ungrouped", groupId: "ungrouped" });
  const rows = sortRows([row("z", "Zeta", "Talos"), row("a", "Alpha", "Unknown publisher"), row("b", "beta", "Talos"), row("e", "Echo", "EvidenceForge")], "publisher");
  expect(groupRows(rows, "publisher").map((group) => [group.id, group.name, group.rows.map((entry) => entry.id)])).toEqual([
    ["publisher:EvidenceForge", "EvidenceForge", ["e"]],
    ["publisher:Talos", "Talos", ["b", "z"]],
    ["publisher:Unknown publisher", "Unknown publisher", ["a"]],
  ]);
  // Without a publisher the group is still named rather than blank.
  expect(groupRows([{ ...row("x", "X", ""), publisher: undefined }], "publisher").map((group) => group.name)).toEqual(["Unknown publisher"]);
  expect(groupRows(rows, "name")).toEqual([{ id: "", name: "", rows }]);
  expect(libraryGroupKey("packs", "publisher", "publisher:Talos")).not.toBe(libraryGroupKey("packs", "project", "publisher:Talos"));
  expect(libraryGroupKey("packs", "project", "case")).not.toBe(libraryGroupKey("scenarios", "project", "case"));
});
