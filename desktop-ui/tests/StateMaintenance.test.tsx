import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import type { UpgradeStatus } from "../src/api";
import { StateMaintenance } from "../src/StateMaintenance";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });
const base: UpgradeStatus = { state: "failed", scope: "private", operation_id: "a".repeat(32), phase: "Upgrading UI state", completed_steps: 2, total_steps: 5, incompatible: true, warning: "Earlier Studio builds will no longer open this state.", error: "Disk is full", backup_path: "/private/verified-backup", can_retry: true, can_restore: true, versions: { database: 0 } };

for (const state of ["pending", "running", "failed", "blocked", "restored", "ready"] as const) {
  test(`maintenance ${state} exposes appropriate recovery controls`, () => {
    const status = { ...base, state, error: state === "pending" || state === "running" ? null : base.error, can_retry: ["failed", "restored"].includes(state), can_restore: state === "failed" };
    const retry = vi.fn(); const restore = vi.fn();
    render(<StateMaintenance status={status} onRetry={retry} onRestore={restore} onWorkspace={vi.fn()} />);
    expect(screen.getByText(base.warning!)).toBeInTheDocument();
    expect(!!screen.queryByRole("button", { name: "Retry upgrade" })).toBe(status.can_retry);
    expect(!!screen.queryByRole("button", { name: "Restore previous UI state" })).toBe(status.can_restore);
    if (state === "pending") {
      expect(retry).not.toHaveBeenCalled();
      fireEvent.click(screen.getByRole("button", { name: "Continue with upgrade" }));
      expect(retry).toHaveBeenCalledOnce();
    }
    if (status.can_retry) { fireEvent.click(screen.getByRole("button", { name: "Retry upgrade" })); expect(retry).toHaveBeenCalledOnce(); }
    if (state === "restored") expect(screen.getByText(/Restoration does not install/)).toBeInTheDocument();
  });
}

test("restoration explains its operation and requires an explicit action", () => {
  const restore = vi.fn();
  vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
  render(<StateMaintenance status={base} onRetry={vi.fn()} onRestore={restore} onWorkspace={vi.fn()} />);
  fireEvent.click(screen.getByRole("button", { name: "Restore previous UI state" }));
  expect(restore).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Restore previous UI state" }));
  expect(restore).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByText("View details"));
  expect(screen.getByText(/Recovery backup:/)).toHaveTextContent(base.backup_path!);
});

test("workspace failure permits choosing another workspace", () => {
  const select = vi.fn();
  render(<StateMaintenance status={{ ...base, scope: "workspace", state: "blocked", can_retry: false, can_restore: false }} onRetry={vi.fn()} onRestore={vi.fn()} onWorkspace={select} />);
  expect(screen.getByRole("button", { name: "Open workspace" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Another workspace path"), { target: { value: "/other/workspace" } });
  fireEvent.click(screen.getByRole("button", { name: "Open workspace" }));
  expect(select).toHaveBeenCalledWith("/other/workspace");
});
