import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, expect, test, vi } from "vitest";
import { DisplayNameField } from "../src/DisplayNameField";
import type { StudioApi } from "../src/api";

afterEach(cleanup);

function Form({ request, name = "northstar", initial = "" }: { request: StudioApi["request"]; name?: string; initial?: string }) {
  const [value, setValue] = useState(initial);
  return <DisplayNameField api={{ request } as StudioApi} label="Display name" value={value} onChange={setValue} disabled={false} placeholder="Optional" source={{ context: { kind: "scenario", name } }} />;
}

test("AI is explicit and returns an editable unsaved suggestion", async () => {
  const request = vi.fn(async () => ({ display_name: "Northstar Health - Credential Theft" }));
  render(<Form request={request as StudioApi["request"]} />);
  expect(request).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Suggest display name with AI" }));
  expect(request).toHaveBeenCalledWith("/v1/assist/display-name", "POST", { context: { kind: "scenario", name: "northstar" } }, 130000);
  expect(screen.getByRole("textbox")).toHaveValue("Northstar Health - Credential Theft");
  expect(screen.getByRole("status")).toHaveTextContent("Review or edit it before saving");
  expect(screen.queryByRole("button", { name: "Suggest display name with AI" })).toBeNull();
  await userEvent.clear(screen.getByRole("textbox"));
  await userEvent.type(screen.getByRole("textbox"), "My own title");
  expect(screen.getByRole("textbox")).toHaveValue("My own title");
  expect(request).toHaveBeenCalledTimes(1);
});

test("late responses never replace manual typing, even when cleared again", async () => {
  let finish: (value: object) => void = () => undefined;
  const request = vi.fn(() => new Promise((resolve) => { finish = resolve; }));
  render(<Form request={request as StudioApi["request"]} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Suggest display name with AI" }));
  expect(screen.getByRole("button")).toBeDisabled();
  expect(screen.getByRole("textbox")).toBeEnabled();
  await user.type(screen.getByRole("textbox"), "My choice");
  await user.clear(screen.getByRole("textbox"));
  await act(async () => { finish({ display_name: "Delayed suggestion" }); });
  expect(screen.getByRole("textbox")).toHaveValue("");
  expect(screen.queryByRole("status")).toBeNull();
});

test("a changed source discards the earlier suggestion", async () => {
  let finish: (value: object) => void = () => undefined;
  const request = vi.fn(() => new Promise((resolve) => { finish = resolve; }));
  const view = render(<Form request={request as StudioApi["request"]} />);
  await userEvent.click(screen.getByRole("button"));
  view.rerender(<Form request={request as StudioApi["request"]} name="another" />);
  await act(async () => { finish({ display_name: "Wrong source's title" }); });
  expect(screen.getByRole("textbox")).toHaveValue("");
});

test("AI failure leaves manual names available and does not retry automatically", async () => {
  const request = vi.fn(async () => { throw new Error("AI is unavailable"); });
  render(<Form request={request as StudioApi["request"]} />);
  await userEvent.click(screen.getByRole("button"));
  expect(screen.getByRole("alert")).toHaveTextContent("AI is unavailable");
  await userEvent.type(screen.getByRole("textbox"), "Manual title");
  expect(screen.getByRole("textbox")).toHaveValue("Manual title");
  expect(screen.queryByRole("alert")).toBeNull();
  expect(request).toHaveBeenCalledTimes(1);
});

test("a supplied name has no sparkle action or automatic AI call", () => {
  const request = vi.fn();
  render(<Form request={request as StudioApi["request"]} initial="Existing name" />);
  expect(screen.queryByRole("button")).toBeNull();
  expect(request).not.toHaveBeenCalled();
});
