import type { StudioJob } from "./api";

/** A finished evaluation is successful only when its saved acceptance passed. */
export function completedSuccessfully(job: StudioJob): boolean {
  return job.status === "completed" && (job.kind === "generation"
    || job.scorecard?.acceptance_passed === true && !job.scorecard.error);
}

/**
 * A job that is over for good: finished, or stopped with no checkpoint to resume. Mirrors the
 * service's `job_cannot_continue`; queued, running, paused and resumable jobs can still continue.
 */
export function cannotContinue(job: StudioJob): boolean {
  return ["completed", "failed", "cancelled"].includes(job.status) || (job.status === "stopped" && !job.can_resume);
}

/** Show failed evaluation outcomes without changing their retained report lifecycle. */
export function jobDisplayStatus(job: StudioJob): string {
  return job.status === "completed" && job.kind === "evaluation"
    && (job.scorecard?.error || job.scorecard?.acceptance_passed === false)
    ? "failed" : job.status;
}
