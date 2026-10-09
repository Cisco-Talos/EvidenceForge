import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test } from "vitest";
import { AffectedItems } from "../src/AffectedItems";
import type { AffectedItem } from "../src/api";

afterEach(cleanup);
test("one bare disclosure starts collapsed and orders categories, names, and numeric versions", async () => {
  const entry = (kind: AffectedItem["kind"], name: string, version = "") => ({ kind, name, version, path: `/${kind}/${name}/${version}`, publisher: "", frozen: false });
  const { container } = render(<AffectedItems items={[
    entry("scenario", "Zebra"), entry("organization_pack", "Bravo"),
    entry("industry_pack", "Zulu"), entry("scenario", "Alpha", "1.2.9"),
    entry("industry_pack", "Alpha"), entry("scenario", "Alpha", "1.2.10"),
    entry("organization_pack", "Alpha"),
  ]} />);
  const details = container.querySelector("details")!;
  expect(details).not.toHaveAttribute("open");
  expect(container.querySelectorAll("details")).toHaveLength(1);
  await userEvent.click(screen.getByText("Affected items (7)"));
  expect(details).toHaveAttribute("open");
  const groups = screen.getAllByRole("region");
  expect(groups.map((group) => group.getAttribute("aria-label"))).toEqual(["Industry packs", "Organization packs", "Scenarios"]);
  expect(within(groups[0]).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Alpha", "Zulu"]);
  expect(within(groups[1]).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Alpha", "Bravo"]);
  expect(within(groups[2]).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Alpha1.2.10", "Alpha1.2.9", "Zebra"]);
  await userEvent.click(screen.getByText("Affected items (7)"));
  expect(details).not.toHaveAttribute("open");
});

test("empty categories are omitted", async () => {
  render(<AffectedItems items={[{ kind: "scenario", name: "Case", path: "/case", version: "", publisher: "", frozen: false }]} />);
  await userEvent.click(screen.getByText("Affected items (1)"));
  expect(screen.getByRole("region", { name: "Scenarios" })).toBeTruthy();
  expect(screen.queryByRole("region", { name: "Industry packs" })).toBeNull();
  expect(screen.queryByRole("region", { name: "Organization packs" })).toBeNull();
});
