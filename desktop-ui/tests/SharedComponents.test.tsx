import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import { Tooltip } from "radix-ui";
import { ConfirmModal, Modal } from "../src/Modal";
import { EmptyState, ErrorBanner } from "../src/Feedback";
import { JobStatusPill, StatusPill, summarizeStates } from "../src/StatusPill";
import type { OperationState } from "../src/ScenarioStates";

const tauri = vi.hoisted(() => ({ native: false, reveal: vi.fn(async () => undefined) }));
vi.mock("@tauri-apps/api/core", async (original) => ({ ...(await original<object>()), isTauri: () => tauri.native }));
vi.mock("@tauri-apps/plugin-opener", () => ({ revealItemInDir: tauri.reveal }));
const { revealAction, SavedPath } = await import("../src/RevealInFinder");

afterEach(() => { cleanup(); tauri.native = false; tauri.reveal.mockClear(); });

const state = (label: string, value: OperationState["state"], detail = `${label} detail`): OperationState => ({ label, state: value, detail });

test("Modal is named by its title, closes on Escape, and stays open while busy", async () => {
  const user = userEvent.setup();
  const onClose = vi.fn();
  const view = render(<Modal title="Rename scenario" description="One sentence." onClose={onClose}><input aria-label="Name" /></Modal>);
  expect(screen.getByRole("dialog", { name: "Rename scenario" })).toHaveAccessibleDescription("One sentence.");
  await user.keyboard("{Escape}");
  expect(onClose).toHaveBeenCalledOnce();
  view.rerender(<Modal title="Rename scenario" busy onClose={onClose} />);
  await user.keyboard("{Escape}");
  expect(onClose).toHaveBeenCalledOnce();
});

test("Modal ignores outside clicks unless dismissal is allowed and honors an explicit accessible name", async () => {
  // Radix disables pointer events outside a modal; click through to reach its outside-click handling.
  const user = userEvent.setup({ pointerEventsCheck: 0 });
  const onClose = vi.fn();
  const view = render(<Modal title="Export alpha" ariaLabel="Export scenario bundle" onClose={onClose} />);
  expect(screen.getByRole("dialog", { name: "Export scenario bundle" })).toBeVisible();
  await user.click(document.body);
  expect(onClose).not.toHaveBeenCalled();
  view.rerender(<Modal title="Command menu" hideTitle dismissOnOutside onClose={onClose} />);
  expect(screen.queryByRole("heading", { name: "Command menu" })).toBeNull();
  await user.click(document.body);
  expect(onClose).toHaveBeenCalledOnce();
});

test("Modal forms submit with Enter and ConfirmModal names its action", async () => {
  const user = userEvent.setup();
  const onSubmit = vi.fn();
  const view = render(<Modal title="New project" onClose={vi.fn()} onSubmit={onSubmit} actions={<button type="submit">Create project</button>}><input aria-label="Project name" /></Modal>);
  await user.type(screen.getByRole("textbox", { name: "Project name" }), "Alpha{Enter}");
  expect(onSubmit).toHaveBeenCalledOnce();
  // The dialog box and its inner form must not share a layout class, or the dialog loses its panel.
  const form = screen.getByRole("dialog").querySelector("form");
  expect(form).toHaveClass("modal-body-form");
  expect(screen.getByRole("dialog")).not.toHaveClass("modal-body-form");
  const onConfirm = vi.fn();
  view.rerender(<ConfirmModal title="Remove from Studio?" confirmLabel="Remove from Studio" onCancel={vi.fn()} onConfirm={onConfirm}><p>Files are kept.</p></ConfirmModal>);
  await user.click(screen.getByRole("button", { name: "Remove from Studio" }));
  expect(onConfirm).toHaveBeenCalledOnce();
});

test("summarizeStates prefers active work, then failures, then the furthest completed stage", () => {
  expect(summarizeStates([state("Validation", "success"), state("Generation", "working"), state("Evaluation", "none")])).toMatchObject({ tone: "info", label: "Generating" });
  expect(summarizeStates([state("Validation", "error"), state("Generation", "success"), state("Evaluation", "none")])).toMatchObject({ tone: "err", label: "Invalid" });
  expect(summarizeStates([state("Validation", "success"), state("Generation", "success"), state("Evaluation", "error", "Failed acceptance · 92/100.")])).toMatchObject({ tone: "err", label: "Failed acceptance" });
  expect(summarizeStates([state("Validation", "success"), state("Generation", "success"), state("Evaluation", "success", "Passed acceptance · 91/100 for this scenario revision.")])).toMatchObject({ tone: "ok", label: "Passed · 91" });
  expect(summarizeStates([state("Validation", "warning", "Current revision is valid with 2 warnings."), state("Generation", "none"), state("Evaluation", "none")])).toMatchObject({ tone: "warn", label: "2 warnings" });
  expect(summarizeStates([state("Validation", "stale"), state("Generation", "none"), state("Evaluation", "none")])).toMatchObject({ tone: "neutral", label: "Stale" });
  const none = summarizeStates([state("Validation", "none"), state("Generation", "none"), state("Evaluation", "none")]);
  expect(none).toMatchObject({ tone: "neutral", label: "Not validated" });
  expect(none.detail).toBe("Validation: Validation detail\nGeneration: Generation detail\nEvaluation: Evaluation detail");
});

test("status pills carry a visible label and expose their detail accessibly", () => {
  render(<Tooltip.Provider><StatusPill tone="warn" label="2 warnings" detail="Validation: valid with 2 warnings" /><JobStatusPill status="running" /></Tooltip.Provider>);
  expect(screen.getByText("2 warnings").closest(".status-pill")).toHaveClass("tone-warn");
  expect(screen.getByLabelText("2 warnings: Validation: valid with 2 warnings")).toBeVisible();
  expect(screen.getByText("Running").closest(".status-pill")).toHaveClass("tone-info");
});

test("empty states and error banners share one layout with an optional action", async () => {
  const onRetry = vi.fn();
  render(<><EmptyState title="No bundles yet" action={<button>Import bundle</button>}>Generate a scenario first.</EmptyState><ErrorBanner onRetry={onRetry}>Could not load assets.</ErrorBanner></>);
  expect(screen.getByRole("heading", { name: "No bundles yet" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Import bundle" })).toBeVisible();
  expect(screen.getByRole("alert")).toHaveTextContent("Could not load assets.");
  await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
  expect(onRetry).toHaveBeenCalledOnce();
});

test("Reveal in Finder is offered only in the native app and reveals the exact path", async () => {
  expect(revealAction("/runs/alpha", vi.fn())).toEqual([]);
  tauri.native = true;
  const [action] = revealAction("/runs/alpha", vi.fn());
  expect(action).toMatchObject({ label: "Reveal in Finder", group: "locate" });
  await action.run?.();
  expect(tauri.reveal).toHaveBeenCalledWith("/runs/alpha");
  expect(revealAction("/missing", vi.fn(), "The source file is missing")[0]).toMatchObject({ disabled: true, reason: "The source file is missing" });
  render(<SavedPath path="/exports/alpha.zip" onError={vi.fn()} />);
  expect(screen.getByText("Saved to /exports/alpha.zip")).toBeVisible();
  await userEvent.setup().click(screen.getByRole("button", { name: "Reveal in Finder" }));
  expect(tauri.reveal).toHaveBeenLastCalledWith("/exports/alpha.zip");
});
