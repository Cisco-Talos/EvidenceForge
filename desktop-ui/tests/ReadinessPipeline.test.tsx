import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import { nextStep, ReadinessPipeline, readinessSteps, type NextStepActions } from "../src/ReadinessPipeline";
import type { OperationState } from "../src/ScenarioStates";

afterEach(cleanup);

const op = (label: string, state: OperationState["state"], detail = ""): OperationState => ({ label, state, detail });
const action = (id: string) => ({ id, label: id, group: "work" as const, run: vi.fn() });
const actions: NextStepActions = { author: action("author"), environment: action("environment"), validate: action("validate"), fix: action("fix"), generate: action("generate"), viewRun: action("view-run"), export: action("export") };
const steps = (overrides: Partial<{ starter: boolean; environment: OperationState; states: OperationState[] }> = {}) => readinessSteps({
  starter: false, conversations: 2, authoring: false, environment: op("Environment", "success"),
  states: [op("Validation", "none"), op("Generation", "none"), op("Evaluation", "none")], ...overrides,
});

test("readiness steps label each stage from the existing operation states", () => {
  const result = steps({ states: [op("Validation", "warning", "Current revision is valid with 2 warnings."), op("Generation", "working"), op("Evaluation", "error", "Failed acceptance · 92/100.")] });
  expect(result.map((entry) => [entry.label, entry.tone, entry.status])).toEqual([
    ["Author", "ok", "2 conversations"], ["Environment", "ok", "Ready"], ["Validate", "warn", "2 warnings"],
    ["Generate", "info", "Generating…"], ["Evaluate", "err", "Failed acceptance"],
  ]);
  expect(steps({ starter: true })[0]).toMatchObject({ tone: "todo", status: "Not started" });
  expect(steps({ states: [op("Validation", "success"), op("Generation", "error", "Generation stopped."), op("Evaluation", "error", "Evaluation failed: crashed")] }).map((entry) => entry.status).slice(3)).toEqual(["Stopped", "Failed"]);
  expect(steps({ states: [op("Validation", "error", "3 validation errors in the current revision."), op("Generation", "none"), op("Evaluation", "success", "Passed acceptance · 91/100 for this scenario revision.")] }).map((entry) => entry.status).slice(2))
    .toEqual(["3 errors", "Not run", "Passed · 91"]);
});

test("the next step follows the pipeline in order and skips work in progress", () => {
  expect(nextStep(steps({ starter: true }), actions, false)?.id).toBe("author");
  expect(nextStep(steps({ environment: op("Environment", "error") }), actions, false)?.id).toBe("environment");
  expect(nextStep(steps(), actions, false)?.id).toBe("validate");
  expect(nextStep(steps({ states: [op("Validation", "error"), op("Generation", "none"), op("Evaluation", "none")] }), actions, true)?.id).toBe("fix");
  expect(nextStep(steps({ states: [op("Validation", "warning", "valid with 1 warning"), op("Generation", "none"), op("Evaluation", "none")] }), actions, true)?.id).toBe("generate");
  expect(nextStep(steps({ states: [op("Validation", "stale"), op("Generation", "success"), op("Evaluation", "success")] }), actions, false)?.id).toBe("validate");
  expect(nextStep(steps({ states: [op("Validation", "working"), op("Generation", "none"), op("Evaluation", "none")] }), actions, false)).toBeNull();
  expect(nextStep(steps({ states: [op("Validation", "success"), op("Generation", "working"), op("Evaluation", "none")] }), actions, false)?.id).toBe("view-run");
  expect(nextStep(steps({ states: [op("Validation", "success"), op("Generation", "success"), op("Evaluation", "none")] }), actions, false)?.id).toBe("view-run");
  expect(nextStep(steps({ states: [op("Validation", "success"), op("Generation", "success"), op("Evaluation", "success")] }), actions, false)?.id).toBe("export");
});

test("the readiness strip names every step and runs the next action", async () => {
  const onStep = vi.fn();
  render(<ReadinessPipeline steps={steps()} next={actions.validate} hint="Forecast · ~28 MB" onStep={onStep} />);
  await userEvent.setup().click(screen.getByRole("button", { name: "Validate: Not validated" }));
  expect(onStep).toHaveBeenCalledWith("validate");
  await userEvent.setup().click(screen.getByRole("button", { name: "validate" }));
  expect(actions.validate.run).toHaveBeenCalledOnce();
  expect(screen.getByText("Forecast · ~28 MB")).toBeVisible();
});
