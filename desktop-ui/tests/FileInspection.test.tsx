import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import { BundleFileBrowser } from "../src/BundleFileBrowser";
import { findingGroups, ValidationPanel } from "../src/components";
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

test.each(["macos_unified_log.ndjson", "macos_endpoint_security.ndjson"])("native output %s is displayed as JSON without changing records", async (filename) => {
  const path = `data/MAC-01/${filename}`;
  const text = '{"time":"2026-10-20T13:00:00Z","event_type":11}\n{"time":"2026-10-20T13:00:01Z","event_type":11}';
  const readTextPreview = vi.fn(async () => ({ text, truncated: false, binary: false }));
  render(<BundleFileBrowser jobId="mac-run" files={{ root: "/bundle", files: [{ path, size: text.length }], truncated: false }} api={{ readTextPreview } as unknown as StudioApi} onClose={vi.fn()} onError={vi.fn()} />);
  const preview = await screen.findByLabelText(`Preview of ${path}`);
  expect(preview).toHaveClass("language-json");
  const lines = preview.querySelectorAll(".bundle-source-line");
  expect(lines).toHaveLength(2);
  expect(lines[0].lastElementChild?.textContent).toBe(text.split("\n")[0]);
  expect(lines[1].lastElementChild?.textContent).toBe(text.split("\n")[1]);
  expect(preview.querySelector(".syntax-key")).toHaveTextContent('"time"');
  expect(readTextPreview).toHaveBeenCalledWith(`/v1/jobs/mac-run/files/${path}`);
});

test("validation findings fold by severity with counts while the summary and repair stay directly visible", async () => {
  const result = { report: { valid: false, scenario: { name: "Example" }, issues: [
    { severity: "info", field_path: "notes", message: "Optional briefing missing" },
    { severity: "warning", field_path: "baseline", message: "Quiet baseline" },
    { severity: "error", field_path: "users.0", message: "Unknown host", suggestion: "Select an existing host" },
    { severity: "warning", field_path: "storyline.2", message: "Late step" },
  ] } } as ValidationResult;
  const onFix = vi.fn();
  const { container } = render(<ValidationPanel result={result} onFix={onFix} />);
  expect(screen.getByText("Needs changes")).toBeVisible();
  expect(screen.getByText("Example · 4 findings")).toBeVisible();
  const groups = [...container.querySelectorAll<HTMLDetailsElement>("details.finding-group")];
  expect(groups.map((group) => [...group.querySelector("summary")!.querySelectorAll("span")].map((node) => node.textContent))).toEqual([["Errors", "1"], ["Warnings", "2"], ["Info", "1"]]);
  expect(groups.every((group) => !group.open)).toBe(true);
  expect(screen.getByText("Unknown host")).not.toBeVisible();
  expect(screen.queryByRole("button", { name: "Validation findings 1 finding" })).not.toBeInTheDocument();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Fix in chat" }));
  expect(onFix).toHaveBeenCalledOnce();
  await user.click(groups[0].querySelector("summary")!);
  expect(groups[0].open).toBe(true);
  expect(screen.getByText("Unknown host")).toBeVisible();
  expect(screen.getByText("Suggested fix: Select an existing host")).toBeVisible();
  expect(screen.getByText("Quiet baseline")).not.toBeVisible();
});

test("findingGroups orders severities error, warning, info and keeps unknown severities last", () => {
  const groups = findingGroups([
    { severity: "INFO", message: "a" }, { severity: "notice", message: "b" }, { message: "c" },
    { severity: "Warning", message: "d" }, { severity: "error", message: "e" }, { severity: "error", message: "f" },
  ]);
  expect(groups.map((group) => [group.severity, group.label, group.issues.map((issue) => issue.message)])).toEqual([
    ["error", "Errors", ["e", "f"]],
    ["warning", "Warnings", ["d"]],
    ["info", "Info", ["a", "c"]],
    ["notice", "Notice", ["b"]],
  ]);
  expect(findingGroups([])).toEqual([]);
});

test("the bundle file list is a folder tree with the selected file's folders open and others folded", async () => {
  const readTextPreview = vi.fn(async () => ({ text: "# Truth", truncated: false, binary: false }));
  const files = [
    { path: "HOST-01/zeek/conn.log", size: 2048 }, { path: "HOST-01/zeek/dns.log", size: 10 },
    { path: "HOST-02/sysmon.xml", size: 3 * 1024 * 1024 }, { path: "docs/GROUND_TRUTH.md", size: 7 },
  ];
  render(<BundleFileBrowser jobId="run" files={{ root: "/bundle", files, truncated: true }} api={{ readTextPreview } as unknown as StudioApi} onClose={vi.fn()} onError={vi.fn()} />);
  await screen.findByLabelText("Preview of docs/GROUND_TRUTH.md");
  const list = screen.getByRole("navigation", { name: "Bundle file list" });
  const folders = () => within(list).getAllByRole("button").filter((button) => button.classList.contains("bundle-folder-row"))
    .map((button) => [button.getAttribute("aria-label"), button.getAttribute("aria-expanded")]);
  // Folders sort before files; only the selected file's folder starts open.
  expect(folders()).toEqual([["docs, 1 file", "true"], ["HOST-01, 2 files", "false"], ["HOST-02, 1 file", "false"]]);
  const truth = within(list).getByRole("button", { name: /^GROUND_TRUTH\.md/ });
  expect(truth).toHaveClass("selected");
  expect(truth).toHaveAttribute("title", "docs/GROUND_TRUTH.md");
  expect(truth.querySelector("span")).toHaveTextContent(/^GROUND_TRUTH\.md$/);
  expect(within(list).queryByRole("button", { name: /^conn\.log/ })).toBeNull();
  expect(screen.getByText("Showing the first 4 files.")).toBeVisible();

  const user = userEvent.setup();
  await user.click(within(list).getByRole("button", { name: "HOST-01, 2 files" }));
  expect(within(list).getByRole("button", { name: "HOST-01, 2 files" })).toHaveAttribute("aria-expanded", "true");
  expect(within(list).getByRole("button", { name: "zeek, 2 files" })).toHaveAttribute("aria-expanded", "false");
  await user.click(within(list).getByRole("button", { name: "zeek, 2 files" }));
  const conn = within(list).getByRole("button", { name: /^conn\.log/ });
  expect(conn).toHaveAttribute("title", "HOST-01/zeek/conn.log");
  expect(conn.querySelector("small")).toHaveTextContent("2.0 KB");
  await user.click(conn);
  expect(readTextPreview).toHaveBeenLastCalledWith("/v1/jobs/run/files/HOST-01/zeek/conn.log");
  expect(conn).toHaveClass("selected");
  await user.click(within(list).getByRole("button", { name: "HOST-02, 1 file" }));
  expect(within(list).getByRole("button", { name: /^sysmon\.xml/ }).querySelector("small")).toHaveTextContent("3.0 MB");
  await user.click(within(list).getByRole("button", { name: "HOST-01, 2 files" }));
  expect(within(list).queryByRole("button", { name: /^conn\.log/ })).toBeNull();
});
