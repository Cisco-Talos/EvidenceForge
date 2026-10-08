import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, expect, test, vi } from "vitest";
import { ReleaseNotesField } from "../src/ReleaseNotesField";
import type { StudioApi } from "../src/api";

afterEach(cleanup);

const reviewed = { digest: "fresh-assets", lifecycle: { status: "draft" } };
function Form({ request, revision = "one", onReviewed = vi.fn() }: { request: StudioApi["request"]; revision?: string; onReviewed?: ReturnType<typeof vi.fn> }) {
  const [value, setValue] = useState("Manual notes");
  return <ReleaseNotesField itemId="draft" revision={revision} value={value} onChange={setValue} onReviewed={onReviewed} disabled={false} api={{ request } as StudioApi} />;
}

test("notes suggestion reads current assets and stays separate until used", async () => {
  const request = vi.fn(async (path: string) => path.includes("/assist/") ? { release_notes: "Suggested notes", findings: ["Exact ancestor unavailable"] } : reviewed);
  const onReviewed = vi.fn();
  render(<Form request={request as StudioApi["request"]} onReviewed={onReviewed} />);
  expect(request).not.toHaveBeenCalled();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Suggest release notes with AI" }));
  expect(onReviewed).toHaveBeenCalledWith(reviewed);
  expect(request).toHaveBeenNthCalledWith(1, "/v1/items/draft/lifecycle");
  expect(request).toHaveBeenNthCalledWith(2, "/v1/assist/release-notes", "POST", { item_id: "draft", expected_digest: "fresh-assets", notes: "Manual notes" }, 130000);
  expect(screen.getByRole("textbox", { name: "Release notes" })).toHaveValue("Manual notes");
  expect(screen.getByText("Exact ancestor unavailable")).toBeVisible();
  await user.type(screen.getByRole("textbox", { name: "Suggested release notes" }), " with my edit");
  await user.click(screen.getByRole("button", { name: "Use suggestion" }));
  expect(screen.getByRole("textbox", { name: "Release notes" })).toHaveValue("Suggested notes with my edit");
  expect(screen.queryByRole("region")).toBeNull();
  expect(request).toHaveBeenCalledTimes(2);
});

test("dismissing a suggestion preserves manual notes", async () => {
  const request = vi.fn(async (path: string) => path.includes("/assist/") ? { release_notes: "Suggested notes", findings: [] } : reviewed);
  render(<Form request={request as StudioApi["request"]} />);
  await userEvent.click(screen.getByRole("button", { name: "Suggest release notes with AI" }));
  await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
  expect(screen.getByRole("textbox", { name: "Release notes" })).toHaveValue("Manual notes");
  expect(screen.queryByRole("region")).toBeNull();
});

for (const change of ["typing", "source", "unmount"] as const) {
  test(`pending suggestion is discarded after ${change}`, async () => {
    let finish: (value: object) => void = () => undefined;
    const request = vi.fn(async (path: string) => path.includes("/assist/") ? new Promise((resolve) => { finish = resolve; }) : reviewed);
    const view = render(<Form request={request as StudioApi["request"]} />);
    await userEvent.click(screen.getByRole("button", { name: "Suggest release notes with AI" }));
    expect(screen.getByRole("textbox", { name: "Release notes" })).toBeEnabled();
    if (change === "typing") {
      await userEvent.type(screen.getByRole("textbox", { name: "Release notes" }), " changed");
    } else if (change === "source") view.rerender(<Form request={request as StudioApi["request"]} revision="two" />);
    else view.unmount();
    await act(async () => { finish({ release_notes: "Delayed notes", findings: [] }); });
    expect(screen.queryByRole("region")).toBeNull();
    if (change !== "unmount") expect(screen.getByRole("textbox", { name: "Release notes" })).toHaveValue(change === "typing" ? "Manual notes changed" : "Manual notes");
  });
}

for (const failure of ["AI unavailable", "Published"] as const) {
  test(`${failure} leaves manual notes usable`, async () => {
    const request = vi.fn(async (path: string) => {
      if (path.includes("/assist/")) throw new Error("AI unavailable");
      return failure === "Published" ? { ...reviewed, lifecycle: { status: "published" } } : reviewed;
    });
    render(<Form request={request as StudioApi["request"]} />);
    await userEvent.click(screen.getByRole("button", { name: "Suggest release notes with AI" }));
    expect(screen.getByRole("alert")).toHaveTextContent(failure === "Published" ? "Create a draft" : "AI unavailable");
    await userEvent.type(screen.getByRole("textbox", { name: "Release notes" }), " updated");
    expect(screen.getByRole("textbox", { name: "Release notes" })).toHaveValue("Manual notes updated");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(request).toHaveBeenCalledTimes(failure === "Published" ? 1 : 2);
  });
}
