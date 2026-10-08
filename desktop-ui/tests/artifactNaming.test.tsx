import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { artifactTitle, draftTitle } from "../src/artifactNaming";
import { scenarioNameError } from "../src/scenarioName";
import { packNameError } from "../src/packName";
import { PackLibrary } from "../src/PackLibrary";
import type { CatalogItem } from "../src/api";

afterEach(cleanup);

test("shared naming preserves full identifiers, leading symbols, case and title fallback", () => {
  for (const name of ["_scenario", "-scenario", "A".repeat(500)]) expect(scenarioNameError(name)).toBeNull();
  expect(packNameError("a".repeat(500))).toBeNull();
  expect(packNameError("Capitalized")).not.toBeNull();
  expect(artifactTitle({ name: "CaseSensitive", display_name: "Friendly — Santé" })).toBe("Friendly — Santé");
  expect(artifactTitle({ name: "CaseSensitive" })).toBe("CaseSensitive");
  expect(draftTitle({ title: "Chat", draft_name: "identifier", draft_display_name: "Friendly Draft" })).toBe("Friendly Draft");
});

test("pack versions stay grouped by exact identity when each release has a different title", () => {
  const pack = (name: string, version: string, display_name: string) => ({ id: name + version, kind: "organization_pack", publisher: "team", publisher_display_name: "Team", name, display_name, version, path: "/" + name + version, pack_source: "workspace", description: "Test", modified_at: 0 } as CatalogItem);
  render(<PackLibrary items={[pack("alpha", "1.0.0", "A Title"), pack("alpha", "2.0.0", "Z Title"), pack("beta", "1.0.0", "M Title")]} drafts={[]} projects={[]} busy={false} expandedGroups={["organization_pack"]} onToggleGroup={vi.fn()} onOpen={vi.fn()} onOpenDraft={vi.fn()} onNew={vi.fn()} onClone={vi.fn()} onExport={vi.fn()} onHide={vi.fn()} onMove={vi.fn()} onMoveDraft={vi.fn()} onDelete={vi.fn()} onNewProject={vi.fn()} onDeleteDraft={vi.fn()} onDragStart={vi.fn()} onDraftDragStart={vi.fn()} onDragEnd={vi.fn()} />);
  expect(screen.getByRole("button", { name: "Open Z Title 2.0.0" })).toBeInTheDocument();
  expect([...document.querySelectorAll("[data-artifact-identity]")].map((row) => row.getAttribute("data-artifact-identity"))).toEqual(["team/beta", "team/alpha", "team/alpha"]);
  expect(screen.getAllByText("team/alpha · drafts & releases")).toHaveLength(1);
});
