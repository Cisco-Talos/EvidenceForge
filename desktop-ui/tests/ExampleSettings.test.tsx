import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { ExampleSettings } from "../src/ExampleSettings";
import type { StudioApi } from "../src/api";

afterEach(cleanup);

test("manual install is available for any workspace and an empty collection is usable", async () => {
  const status = { directory: "/app/examples", bundled_releases: 0, automatic_updates: false, error: "" };
  const request = vi.fn(async () => status);
  const onSaved = vi.fn(async () => undefined);
  const onOpenFolder = vi.fn(async () => undefined);
  render(<ExampleSettings workspace="/custom" api={{ request } as unknown as StudioApi} onSaved={onSaved} onOpenFolder={onOpenFolder} onError={vi.fn()} />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Open bundled examples folder" }));
  expect(onOpenFolder).toHaveBeenCalledWith("/app/examples");
  await user.click(screen.getByRole("button", { name: "Install/update examples" }));
  expect(request).toHaveBeenCalledWith("/v1/examples/install", "POST", { workspace: "/custom" }, 180000);
  expect(await screen.findByRole("status")).toHaveTextContent("does not include any examples yet");
  expect(onSaved).toHaveBeenCalledOnce();
});

test("installation errors expose retry and switching workspaces reloads eligibility", async () => {
  let error = "Release conflict";
  const request = vi.fn(async () => ({ directory: "/app/examples", bundled_releases: 2, automatic_updates: true, error }));
  const api = { request } as unknown as StudioApi;
  const view = (workspace: string) => <ExampleSettings workspace={workspace} api={api} onSaved={async () => undefined} onOpenFolder={async () => undefined} onError={vi.fn()} />;
  const rendered = render(view("/default"));
  expect(await screen.findByRole("alert")).toHaveTextContent("Release conflict");
  error = "";
  await userEvent.setup().click(screen.getByRole("button", { name: "Retry install/update examples" }));
  await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  expect(screen.getByText(/added here automatically/)).toBeInTheDocument();
  const before = request.mock.calls.length;
  rendered.rerender(view("/custom"));
  await waitFor(() => expect(request.mock.calls.length).toBeGreaterThan(before));
});
