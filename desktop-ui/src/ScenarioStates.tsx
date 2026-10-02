import { CheckCircle2, CircleMinus, Clock3, LoaderCircle, TriangleAlert, XCircle } from "lucide-react";
import { Tooltip } from "radix-ui";
import { CatalogItem, StudioJob, StudioSnapshot, ValidationRecord } from "./api";

type State = "none" | "stale" | "working" | "success" | "warning" | "error";
interface OperationState { label: string; state: State; detail: string }

function latest(jobs: StudioJob[]): StudioJob | undefined {
  return [...jobs].sort((a, b) => (b.started_at || b.created_at || 0) - (a.started_at || a.created_at || 0))[0];
}

function jobState(label: string, job: StudioJob | undefined, stale: boolean): OperationState {
  if (!job) return { label, state: stale ? "stale" : "none", detail: stale ? `${label} was completed for an older scenario revision.` : `${label} has not been run.` };
  if (job.status === "queued" || job.status === "running" || job.status === "paused") {
    return { label, state: "working", detail: `${label} is ${job.status}.` };
  }
  if (job.status === "completed") {
    if (job.kind === "evaluation") {
      const report = job.scorecard;
      if (report?.error) return { label, state: "error", detail: `Evaluation report is unavailable: ${report.error}` };
      const score = report?.overall_score == null ? "" : ` · ${report.overall_score.toFixed(0)}/100`;
      if (report?.acceptance_passed === false) return { label, state: "error", detail: `Failed acceptance${score}. One or more required checks failed for this scenario revision.` };
      if (report?.acceptance_passed === true) return { label, state: "success", detail: `Passed acceptance${score} for this scenario revision.` };
      return { label, state: "warning", detail: `Evaluation completed${score}, but acceptance is ${report ? "indeterminate" : "unavailable"}.` };
    }
    return { label, state: "success", detail: `${label} completed for this scenario revision.` };
  }
  return { label, state: "error", detail: `${label} ${job.status}${job.status_message ? `: ${job.status_message}` : "."}` };
}

function validationState(item: CatalogItem, record?: ValidationRecord, dependencyFingerprint?: string, dependencyChangedAt = 0): OperationState {
  if (!record) return { label: "Validation", state: "none", detail: "This scenario has not been validated in Studio." };
  if (record.source_sha256 !== item.source_sha256 || !!record.dependency_sha256 && !!dependencyFingerprint && record.dependency_sha256 !== dependencyFingerprint || !record.dependency_sha256 && dependencyChangedAt > record.completed_at) {
    return { label: "Validation", state: "stale", detail: "Validation predates the latest scenario or dependency change." };
  }
  const counts = record.result.report?.severity_counts as { warning?: number; error?: number } | undefined;
  if (record.result.exit_code !== 0 || (counts?.error || 0) > 0) {
    return { label: "Validation", state: "error", detail: `${counts?.error || "Some"} validation errors in the current revision.` };
  }
  if ((counts?.warning || 0) > 0) {
    return { label: "Validation", state: "warning", detail: `Current revision is valid with ${counts?.warning} warnings.` };
  }
  return { label: "Validation", state: "success", detail: "Current revision passed validation." };
}

export function generationIsCurrent(job: StudioJob, item: CatalogItem, snapshot: StudioSnapshot): boolean {
  const health = snapshot.dependencies?.[item.id];
  return job.source_sha256 === item.source_sha256 && (job.dependency_sha256
    ? !health || job.dependency_sha256 === health.fingerprint
    : (job.submitted_at || job.created_at || job.started_at || 0) >= (health?.changed_at || 0));
}

export function scenarioStates(item: CatalogItem, snapshot: StudioSnapshot): OperationState[] {
  const generations = snapshot.jobs.filter((job) => job.kind === "generation" && job.scenario === item.path);
  const changedAt = snapshot.dependencies?.[item.id]?.changed_at || 0;
  const currentGenerations = generations.filter((job) => generationIsCurrent(job, item, snapshot));
  const generation = latest(currentGenerations);
  const currentIds = new Set(currentGenerations.map((job) => job.id));
  const allIds = new Set(generations.map((job) => job.id));
  const evaluations = snapshot.jobs.filter((job) => job.kind === "evaluation" && !!job.generation_id && allIds.has(job.generation_id));
  const currentEvaluations = evaluations.filter((job) => !!job.generation_id && currentIds.has(job.generation_id));
  return [
    validationState(item, snapshot.validations[item.id], snapshot.dependencies?.[item.id]?.fingerprint, changedAt),
    jobState("Generation", generation, generations.some((job) => job.status === "completed")),
    jobState("Evaluation", latest(currentEvaluations), evaluations.some((job) => job.status === "completed")),
  ];
}

const icons = {
  none: CircleMinus,
  stale: Clock3,
  working: LoaderCircle,
  success: CheckCircle2,
  warning: TriangleAlert,
  error: XCircle,
};

export function OperationStatus({ status, compact = true, focusable = true }: { status: OperationState; compact?: boolean; focusable?: boolean }) {
  const { label, state, detail } = status;
  const Icon = icons[state];
  return <Tooltip.Root>
    <Tooltip.Trigger asChild><span className={`state-icon state-${state}`} tabIndex={focusable ? 0 : undefined} aria-label={`${label}: ${detail}`}><Icon size={compact ? 16 : 15} />{!compact && <small>{label}</small>}</span></Tooltip.Trigger>
    <Tooltip.Portal><Tooltip.Content className="state-tooltip" sideOffset={6}>{detail}<Tooltip.Arrow className="state-tooltip-arrow" /></Tooltip.Content></Tooltip.Portal>
  </Tooltip.Root>;
}

export function ScenarioStates({ item, snapshot, compact = false }: { item: CatalogItem; snapshot: StudioSnapshot; compact?: boolean }) {
  return <div className={`scenario-states ${compact ? "compact" : ""}`} aria-label="Scenario operation status">
    {scenarioStates(item, snapshot).map((status) => <OperationStatus key={status.label} status={status} compact={compact} />)}
  </div>;
}
