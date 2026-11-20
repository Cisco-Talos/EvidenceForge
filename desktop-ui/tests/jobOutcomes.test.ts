import { expect, test } from "vitest";
import type { StudioJob } from "../src/api";
import { cannotContinue } from "../src/jobOutcomes";

const job = (status: string, can_resume?: boolean) => ({ id: status, kind: "generation", status, status_message: "", output_root: "/run", can_resume }) as StudioJob;

test("cannotContinue covers finished jobs and stopped jobs without a checkpoint only", () => {
  expect(["completed", "failed", "cancelled"].map((status) => cannotContinue(job(status)))).toEqual([true, true, true]);
  expect(cannotContinue(job("stopped", false))).toBe(true);
  expect(cannotContinue(job("stopped"))).toBe(true);
  expect(cannotContinue(job("stopped", true))).toBe(false);
  expect(["queued", "running", "paused"].map((status) => cannotContinue(job(status, false)))).toEqual([false, false, false]);
  // A completed evaluation with a failed acceptance is still finished history.
  expect(cannotContinue({ ...job("completed"), kind: "evaluation", scorecard: { overall_score: 40, acceptance_passed: false } } as StudioJob)).toBe(true);
});
