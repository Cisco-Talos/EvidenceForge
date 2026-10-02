import type { StudioJob } from "./api";

/** Keep a run in its original place when it starts, pauses, or resumes. */
export function jobSubmittedAt(job: StudioJob): number {
  if (job.submitted_at) return job.submitted_at;
  if (job.kind === "evaluation") return job.created_at || 0;
  // Older generation records have no submission time. Their output directory
  // was named when they were queued, while started_at can change on resume.
  const label = job.output_root.split(/[\\/]/).slice(-1)[0]?.match(
    /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})-[0-9a-f]{8}$/i,
  );
  if (label) {
    const [, year, month, day, hour, minute, second] = label;
    return new Date(+year, +month - 1, +day, +hour, +minute, +second).getTime() / 1000;
  }
  return job.created_at || job.started_at || 0;
}

export function chronologicalJobs(jobs: StudioJob[]): StudioJob[] {
  return [...jobs].sort((left, right) =>
    jobSubmittedAt(left) - jobSubmittedAt(right) || left.id.localeCompare(right.id));
}

/** Newest submissions first; process restarts never move an existing row. */
export function recentJobs(jobs: StudioJob[]): StudioJob[] {
  return [...jobs].sort((left, right) =>
    jobSubmittedAt(right) - jobSubmittedAt(left) || left.id.localeCompare(right.id));
}
