import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { ArtifactTitle } from "../src/ArtifactTitle";
import type { StudioApi } from "../src/api";

afterEach(cleanup);

function fixture(displayName: string | null = "Northstar Health — Credential Theft") {
  const request = vi.fn(async () => ({ display_name: "Northstar Health — Account Abuse" }));
  const onSave = vi.fn(async (_value: string | null) => undefined);
  const prepareSource = vi.fn(async () => ({ item_id: "draft", expected_digest: "current-assets" }));
  render(<ArtifactTitle name="stable-scenario-id" displayName={displayName} api={{ request } as unknown as StudioApi} source={{ item_id: "draft", expected_digest: "root-hash" }} prepareSource={prepareSource} onSave={onSave} hint="Saving creates a new draft. This published release keeps its title." />);
  return { request, onSave, prepareSource, user: userEvent.setup() };
}

test("clicking the displayed title opens that title and exposes AI without changing identity", async () => {
  const { user, onSave, request } = fixture();
  await user.click(screen.getByRole("button", { name: "Edit display name Northstar Health — Credential Theft" }));
  expect(screen.getByRole("textbox", { name: "Workspace display name" })).toHaveValue("Northstar Health — Credential Theft");
  expect(screen.getByRole("button", { name: "Suggest display name with AI" })).toBeEnabled();
  expect(screen.getByText("Identifier: stable-scenario-id")).toBeVisible();
  expect(screen.getByText(/Saving creates a new draft/)).toBeVisible();
  await user.clear(screen.getByRole("textbox"));
  await user.type(screen.getByRole("textbox"), "My Healthcare Scenario");
  await user.click(screen.getByRole("button", { name: "Save workspace display name" }));
  expect(onSave).toHaveBeenCalledWith("My Healthcare Scenario");
  expect(request).not.toHaveBeenCalled();
});

test("existing names can be suggested again and remain unsaved until accepted", async () => {
  const { user, onSave, request, prepareSource } = fixture();
  await user.click(screen.getByRole("button", { name: /Edit display name/ }));
  await user.click(screen.getByRole("button", { name: "Suggest display name with AI" }));
  expect(prepareSource).toHaveBeenCalledTimes(2);
  expect(request).toHaveBeenCalledWith("/v1/assist/display-name", "POST", { item_id: "draft", expected_digest: "current-assets" }, 130000);
  expect(screen.getByRole("textbox")).toHaveValue("Northstar Health — Account Abuse");
  expect(onSave).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Cancel display name edit" }));
  expect(screen.getByRole("heading")).toHaveTextContent("Northstar Health — Credential Theft");
  expect(onSave).not.toHaveBeenCalled();
});

test("unchanged titles close without creating a draft and empty titles explicitly clear the field", async () => {
  const { user, onSave } = fixture();
  await user.click(screen.getByRole("button", { name: /Edit display name/ }));
  await user.click(screen.getByRole("button", { name: "Save workspace display name" }));
  expect(onSave).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: /Edit display name/ }));
  await user.clear(screen.getByRole("textbox"));
  await user.click(screen.getByRole("button", { name: "Save workspace display name" }));
  expect(onSave).toHaveBeenCalledWith(null);
});

test("without a display name the identifier remains a fallback, not a required new title", async () => {
  const { user, onSave } = fixture(null);
  await user.click(screen.getByRole("button", { name: "Edit display name stable-scenario-id" }));
  expect(screen.getByRole("textbox")).toHaveValue("");
  expect(screen.getByRole("textbox")).toHaveAttribute("placeholder", "stable-scenario-id");
  await user.keyboard("{Escape}");
  expect(onSave).not.toHaveBeenCalled();
});

test("editing during AI assistance takes precedence over a delayed replacement", async () => {
  let finish: (value: object) => void = () => undefined;
  const request = vi.fn(() => new Promise((resolve) => { finish = resolve; }));
  render(<ArtifactTitle name="id" displayName="Existing title" api={{ request } as unknown as StudioApi} source={{ context: { kind: "scenario", name: "id" } }} onSave={vi.fn()} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /Edit display name/ }));
  await user.click(screen.getByRole("button", { name: "Suggest display name with AI" }));
  const editor = screen.getByRole("form", { name: "Edit workspace display name" });
  await user.clear(within(editor).getByRole("textbox"));
  await user.type(within(editor).getByRole("textbox"), "My choice");
  await act(async () => { finish({ display_name: "Delayed title" }); });
  expect(screen.getByRole("textbox")).toHaveValue("My choice");
});

test("identifier sparkle derives a valid name without a request and requires an explicit save", async () => {
  const { user, request, onSave } = fixture();
  await user.click(screen.getByRole("button", { name: /Edit display name/ }));
  expect(screen.queryByRole("textbox", { name: "Identifier" })).toBeNull();
  await user.click(screen.getByText("Change identifier"));
  await user.click(await screen.findByRole("button", { name: "Suggest identifier" }));
  expect(screen.getByRole("textbox", { name: "Identifier" })).toHaveValue("northstar-health-credential-theft");
  expect(request).not.toHaveBeenCalled();
  expect(onSave).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Save workspace names" }));
  expect(onSave).toHaveBeenCalledWith("Northstar Health — Credential Theft", "northstar-health-credential-theft");
});

test("pack identifier edits review consumers and reject invalid names", async () => {
  const onSave = vi.fn();
  const prepareIdentifier = vi.fn(async () => ({ affected: [{ kind: "scenario" as const, name: "Consumer", path: "/consumer", publisher: "", version: "", frozen: false }], problems: [] }));
  render(<ArtifactTitle name="health" displayName="Healthcare" kind="pack" api={{ request: vi.fn() } as unknown as StudioApi} source={{ context: { kind: "industry", name: "health" } }} prepareIdentifier={prepareIdentifier} onSave={onSave} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /Edit display name/ }));
  await user.click(screen.getByText("Change identifier"));
  await waitFor(() => expect(prepareIdentifier).toHaveBeenCalledOnce());
  expect(await screen.findByText(/1 other artifact references/)).toBeVisible();
  await user.clear(screen.getByRole("textbox", { name: "Identifier" }));
  await user.type(screen.getByRole("textbox", { name: "Identifier" }), "Invalid Name");
  await user.click(screen.getByRole("button", { name: "Save workspace names" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("lowercase letters");
  expect(onSave).not.toHaveBeenCalled();
});
