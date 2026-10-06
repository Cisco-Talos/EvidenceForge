import type { StudioJob } from "./api";

/** A finished evaluation is successful only when its saved acceptance passed. */
export function completedSuccessfully(job: StudioJob): boolean {
  return job.status === "completed" && (job.kind === "generation"
    || job.scorecard?.acceptance_passed === true && !job.scorecard.error);
}

/** Show failed evaluation outcomes without changing their retained report lifecycle. */
export function jobDisplayStatus(job: StudioJob): string {
  return job.status === "completed" && job.kind === "evaluation"
    && (job.scorecard?.error || job.scorecard?.acceptance_passed === false)
    ? "failed" : job.status;
}
