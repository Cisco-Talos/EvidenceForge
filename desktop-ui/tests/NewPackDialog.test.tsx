import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { NewPackDialog } from "../src/NewPackDialog";
import { packNameError } from "../src/packName";
import type { PackCreation, StudioApi } from "../src/api";

afterEach(() => cleanup());

test("a suggested pack title stays unsaved until creation", async () => {
  const created = { item: { id: "pack" }, conversation: { id: "chat" } } as PackCreation;
  const request = vi.fn(async (path: string) => path === "/v1/packs/publisher" ? { configured: false } : path === "/v1/assist/display-name" ? { display_name: "Northstar Health" } : created);
  render(<NewPackDialog kind="organization_pack" initialProjectId="" projects={[]} api={{ request } as unknown as StudioApi} onCreated={vi.fn(async () => undefined)} onClose={vi.fn()} />);
  const user = userEvent.setup();
  await user.type(screen.getByRole("textbox", { name: "Pack Name" }), "northstar-health");
  await user.type(screen.getByRole("textbox", { name: "Pack description" }), "Regional healthcare organization");
  await user.click(screen.getByRole("button", { name: "Suggest display name with AI" }));
  expect(screen.getByRole("textbox", { name: "Pack display name" })).toHaveValue("Northstar Health");
  expect(request).not.toHaveBeenCalledWith("/v1/packs", expect.anything(), expect.anything(), expect.anything());
  await user.click(screen.getByRole("button", { name: "Create pack" }));
  expect(request).toHaveBeenLastCalledWith("/v1/packs", "POST", { kind: "organization_pack", name: "northstar-health", display_name: "Northstar Health", description: "Regional healthcare organization", project_id: null }, 190000);
});

test.each(["Invalid", "name with space", "../escape", "under_score", "-starts-dash"])("invalid pack name %s is rejected", (name) => {
  expect(packNameError(name)).not.toBeNull();
});

test("creation accepts optional publisher details, allows empty details, and retains project selection after errors", async () => {
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
  expect(screen.getByRole("button", { name: "Create pack" })).toBeEnabled();
  await user.type(screen.getByRole("textbox", { name: "Publisher ID" }), "test-team");
  await user.type(screen.getByRole("textbox", { name: "Author display name" }), "Test Team");
  await user.click(screen.getByRole("button", { name: "Create pack" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Pack name already exists");
  expect(screen.getByRole("combobox", { name: "Project for new pack" })).toHaveValue("project");
  await user.click(screen.getByRole("button", { name: "Create pack" }));
  await waitFor(() => expect(onCreated).toHaveBeenCalledWith(created, ""));
  expect(request).toHaveBeenLastCalledWith("/v1/packs", "POST", { kind: "industry_pack", name: "industry-one", description: "Test sector", project_id: "project", publisher: "test-team", publisher_display_name: "Test Team" }, 190000);
});

test("creation accepts a long identifier with a friendly title and no publisher", async () => {
  const created = { item: { id: "pack" }, conversation: { id: "chat" } } as PackCreation;
  const request = vi.fn(async (path: string) => path === "/v1/packs/publisher" ? { configured: false } : created);
  render(<NewPackDialog kind="industry_pack" projects={[]} api={{ request } as unknown as StudioApi} onCreated={vi.fn(async () => undefined)} onClose={vi.fn()} />);
  const user = userEvent.setup();
  const name = "a".repeat(300);
  await user.type(screen.getByRole("textbox", { name: "Pack Name" }), name);
  await user.type(screen.getByRole("textbox", { name: "Pack display name" }), "Friendly Pack — Santé");
  await user.type(screen.getByRole("textbox", { name: "Pack description" }), "Test sector");
  await user.click(screen.getByRole("button", { name: "Create pack" }));
  expect(request).toHaveBeenLastCalledWith("/v1/packs", "POST", { kind: "industry_pack", name, display_name: "Friendly Pack — Santé", description: "Test sector", project_id: null }, 190000);
});
