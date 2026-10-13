import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { ActionShortcut, ObjectMenu, type ObjectAction } from "../src/ObjectActions";
import { projectAssignmentAction } from "../src/CatalogObjectMenu";

afterEach(cleanup);

test("shortcuts and grouped menus invoke the same action without toggling a summary", async () => {
  const run = vi.fn();
  const action: ObjectAction = { id: "work", label: "Validate", group: "work", run };
  const { container } = render(<details><summary>Example<ActionShortcut action={action} /><ObjectMenu label="Example actions" actions={[
    { id: "delete", label: "Delete", group: "remove", disabled: true, reason: "Finish active work first" },
    action,
    { id: "open", label: "Open", group: "inspect" },
  ]} /></summary></details>);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Validate" }));
  await user.click(screen.getByRole("button", { name: "Example actions" }));
  expect(screen.getAllByRole("menuitem").map((item) => item.getAttribute("aria-label"))).toEqual(["Open", "Validate", "Delete"]);
  const removal = screen.getByRole("menuitem", { name: "Delete" });
  expect(removal).toHaveAttribute("data-disabled");
  expect(removal).toHaveTextContent("Finish active work first");
  expect(removal.querySelector(".lucide-trash-2")).not.toBeNull();
  await user.click(screen.getByRole("menuitem", { name: "Validate" }));
  expect(run).toHaveBeenCalledTimes(2);
  expect(container.querySelector("details")).not.toHaveAttribute("open");
});

test("project submenu selects the exact project and closes the menu", async () => {
  const move = vi.fn();
  render(<ObjectMenu label="Example actions" actions={[projectAssignmentAction([{ id: "clinic", name: "Clinic" }], move)]} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Example actions" }));
  await user.click(screen.getByRole("menuitem", { name: "Move to project" }));
  await user.click(await screen.findByRole("menuitem", { name: "Clinic" }));
  expect(move).toHaveBeenCalledWith("clinic");
  expect(screen.queryByRole("menu")).toBeNull();
});
