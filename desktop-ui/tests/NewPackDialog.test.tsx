import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { NewPackDialog } from "../src/NewPackDialog";
import { packNameError } from "../src/packName";
import type { PackCreation, StudioApi } from "../src/api";

afterEach(() => cleanup());

test.each(["Invalid", "name with space", "../escape", "under_score", "-starts-dash", "a".repeat(81)])("invalid pack name %s is rejected", (name) => {
  expect(packNameError(name)).not.toBeNull();
});

test("creation collects an explicit author once, allows empty details, and retains project selection after errors", async () => {
  const created = { item: { id: "pack" }, conversation: { id: "chat" } } as PackCreation;
  let attempts = 0;
  const request = vi.fn(async (path: string) => {
    if (path === "/v1/packs/publisher") return { configured: false };
    if (++attempts === 1) throw new Error("Pack name already exists");
    return created;
  });
  const onCreated = vi.fn(async () => undefined);
  render(<NewPackDialog kind="industry_pack" initialProjectId="project" projects={[{ id: "project", workspace: "/workspace", name: "Training", description: "", updated_at: 0 }]} api={{ request } as unknown as StudioApi} onCreated={onCreated} onClose={vi.fn()} />);
  const user = userEvent.setup();
  await user.type(screen.getByRole("textbox", { name: "Pack Name" }), "industry-one");
  await user.type(screen.getByRole("textbox", { name: "Pack description" }), "Test sector");
  expect(screen.getByRole("button", { name: "Create pack" })).toBeDisabled();
  await user.type(screen.getByRole("textbox", { name: "Publisher ID" }), "test-team");
  await user.type(screen.getByRole("textbox", { name: "Author display name" }), "Test Team");
  await user.click(screen.getByRole("button", { name: "Create pack" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Pack name already exists");
  expect(screen.getByRole("combobox", { name: "Project for new pack" })).toHaveValue("project");
  await user.click(screen.getByRole("button", { name: "Create pack" }));
  await waitFor(() => expect(onCreated).toHaveBeenCalledWith(created, ""));
  expect(request).toHaveBeenLastCalledWith("/v1/packs", "POST", { kind: "industry_pack", name: "industry-one", description: "Test sector", project_id: "project", publisher: "test-team", publisher_display_name: "Test Team" }, 190000);
});
