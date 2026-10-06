import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { BundleFileBrowser } from "../src/BundleFileBrowser";
import { ValidationPanel } from "../src/components";
import type { StudioApi, ValidationResult } from "../src/api";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function viewer(text: string, initialLine: number, truncated = false) {
  const readTextPreview = vi.fn(async () => ({ text, truncated, binary: false }));
  const api = { readTextPreview } as unknown as StudioApi;
  const props = { kind: "declarations" as const, jobId: "scenario", files: { root: "Captured input", files: [{ path: "revision/sources/example.yaml", size: text.length }], truncated: false }, initialLine, api, onClose: vi.fn(), onError: vi.fn() };
  return { ...render(<BundleFileBrowser {...props} />), props, readTextPreview };
}

test("declaration jump highlights the exact line, retains preceding context, and allows manual scrolling", async () => {
  vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (this: Element) {
    const line = this.classList.contains("bundle-source-line") ? Number(this.querySelector(".line-number")?.textContent) : 0;
    const top = line ? (line - 1) * 20 + 12 : 0;
    return { top, bottom: top + 20, left: 0, right: 100, width: 100, height: 20, x: 0, y: top, toJSON: () => ({}) };
  });
  const text = Array.from({ length: 150 }, (_, index) => `value_${index + 1}: repeated`).join("\n");
  const { rerender, props } = viewer(text, 100);
  const match = await screen.findByLabelText("Matched declaration, line 100");
  expect(match).toHaveClass("matched-line");
  expect(match).toHaveTextContent("value_100: repeated");
  const source = screen.getByLabelText("Preview of revision/sources/example.yaml");
  expect(source.scrollTop).toBe(96 * 20);
  source.scrollTop = 200;
  rerender(<BundleFileBrowser {...props} />);
  expect(source.scrollTop).toBe(200);
});

test("late declarations load bounded source bytes and keep absolute line numbers", async () => {
  const text = Array.from({ length: 5100 }, (_, index) => `# ${index + 1} ${"padding ".repeat(10)}`).join("\n");
  const { readTextPreview } = viewer(text, 5001);
  expect(await screen.findByLabelText("Matched declaration, line 5001")).toHaveTextContent("# 5001");
  expect(readTextPreview).toHaveBeenCalledWith("/v1/environment/scenario/declarations/files/revision/sources/example.yaml", text.length + 1);
  const source = screen.getByLabelText("Preview of revision/sources/example.yaml");
  expect(source.firstElementChild?.querySelector(".line-number")).toHaveTextContent("4998");
  expect(source.querySelectorAll(".bundle-source-line").length).toBeLessThanOrEqual(4000);
  expect(screen.getByText("Showing lines 4998–5100 of 5100.", { exact: false })).toBeVisible();
});

test("an unavailable declaration line is reported without highlighting a different line", async () => {
  viewer("first: value", 9000, true);
  expect(await screen.findByText("Line 9000 is outside this preview.")).toBeVisible();
  expect(document.querySelector(".matched-line")).toBeNull();
});

test("validation findings and repair are directly visible", async () => {
  const result = { report: { valid: false, scenario: { name: "Example" }, issues: [{ severity: "error", field_path: "users.0", message: "Unknown host", suggestion: "Select an existing host" }] } } as ValidationResult;
  const onFix = vi.fn();
  render(<ValidationPanel result={result} onFix={onFix} />);
  expect(screen.getByText("Needs changes")).toBeVisible();
  expect(screen.getByText("Unknown host")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Validation findings 1 finding" })).not.toBeInTheDocument();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Fix in chat" }));
  expect(onFix).toHaveBeenCalledOnce();
});
