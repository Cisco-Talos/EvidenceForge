import type { CatalogItem, DependencyHealth, ImportedBundle, StudioJob, StudioSnapshot, ValidationResult } from "./api";
import { formatBundleSize, formatTime } from "./components";
import { recentJobs, jobSubmittedAt } from "./jobOrder";
import { jobDisplayStatus } from "./jobOutcomes";
import { generationInputs, generationIsCurrent, jobState, type OperationState, type RunInputStatus } from "./ScenarioStates";

export interface SectionSummary {
  headline: string; detail: string; inputs?: RunInputStatus;
  score?: { headline: string; status: OperationState; attempt?: string };
}

export function countLabel(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** Describe the latest submission, even when an older run finished more recently. */
export function latestJob(jobs: StudioJob[]): StudioJob | undefined {
  return recentJobs(jobs)[0];
}

/** A process failure cannot replace the latest completed, readable quality report. */
export function latestSavedEvaluation(evaluations: StudioJob[]): StudioJob | undefined {
  return latestJob(evaluations.filter((job) => job.status === "completed" && job.scorecard && !job.scorecard.error));
}

export function jobStatusCounts(jobs: StudioJob[]): string {
  return ["running", "queued", "paused", "completed", "failed", "stopped", "cancelled"]
    .map((status) => ({ status, count: jobs.filter((job) => jobDisplayStatus(job) === status).length }))
    .filter(({ count }) => count > 0).map(({ status, count }) => `${count} ${status}`).join(" · ");
}

function runContext(job: StudioJob, item: CatalogItem, snapshot: StudioSnapshot): string {
  const time = jobSubmittedAt(job);
  return [`Latest run #${job.id.slice(0, 8)}`, time ? formatTime(time) : "Time unknown",
    generationIsCurrent(job, item, snapshot) && "Current revision"].filter(Boolean).join(" · ");
}

/** Operation outcome and input freshness are separate facts. */
export function latestRunState(label: string, job: StudioJob | undefined, current = true): OperationState {
  const state = jobState(label, job, false);
  if (!job || current) return state;
  return { ...state, detail: `${state.detail.replace("this scenario revision", "the run's captured data")} Current-input freshness is shown separately.` };
}

export function generationSummary(job: StudioJob | undefined, item: CatalogItem, snapshot: StudioSnapshot, size: number | null | undefined, estimate?: number): SectionSummary {
  if (!job) return { headline: estimate == null ? "Not generated" : `Estimated data ${formatBundleSize(estimate)}`, detail: "No runs yet" };
  const progress = job.progress;
  const hours = progress?.total_hours ? `${progress.completed_hours} of ${progress.total_hours} simulated hours · ${Math.min(100, Math.round(progress.completed_hours / progress.total_hours * 100))}%` : "";
  const status = job.status[0].toUpperCase() + job.status.slice(1);
  return { headline: [status, job.status !== "completed" && hours, size != null ? `${job.status === "completed" ? "Generated data" : "Partial data"} ${formatBundleSize(size)}` : job.status === "completed" ? "Size unavailable" : ""].filter(Boolean).join(" · "),
    detail: [runContext(job, item, snapshot), (job.status !== "completed" || !generationIsCurrent(job, item, snapshot)) && estimate != null ? `Current estimate ${formatBundleSize(estimate)}` : ""].filter(Boolean).join(" · "), inputs: generationInputs(job, item, snapshot) };
}

/** A score only describes the generation it evaluated, never a newer unevaluated run. */
export function scoringSummary(generation: StudioJob | undefined, evaluation: StudioJob | undefined, item: CatalogItem, snapshot: StudioSnapshot): SectionSummary {
  if (!generation) return { headline: "Not evaluated", detail: "No generated run yet" };
  const context = runContext(generation, item, snapshot);
  const inputs = generationInputs(generation, item, snapshot);
  if (!evaluation) return { headline: "Not evaluated", detail: `${context}${generation.status === "completed" ? "" : ` · Generation ${generation.status}`}`, inputs };
  const report = evaluation.scorecard;
  const status = report?.acceptance_passed === true ? "Passed" : report?.acceptance_passed === false ? "Failed" : "Indeterminate";
  const headline = evaluation.status === "completed" && report && !report.error
    ? `${report.overall_score?.toFixed(0) ?? "N/A"}/100 · ${status}${report.total_records == null ? "" : ` · ${report.total_records.toLocaleString()} records`}`
    : report?.error ? "Score report unavailable" : `Evaluation ${evaluation.status}`;
  return { headline, detail: `${context} · Evaluation #${evaluation.id.slice(0, 8)}`, inputs };
}

/** Summarize generation and evaluation of the same latest run, plus all owned/imported data. */
export function runsSummary(jobs: StudioJob[], imports: ImportedBundle[], evaluations: StudioJob[], item: CatalogItem, snapshot: StudioSnapshot, sizes: Record<string, number | null>, estimate?: number): SectionSummary {
  const latest = latestJob(jobs);
  if (!latest && imports.length) return bundleSummary(jobs, imports, sizes);
  const generation = generationSummary(latest, item, snapshot, latest ? sizes[latest.id] : null, estimate);
  const linked = evaluations.filter((job) => job.generation_id === latest?.id);
  const evaluation = latestJob(linked);
  const saved = latestSavedEvaluation(linked);
  const score = scoringSummary(latest, saved || evaluation, item, snapshot);
  const active = jobs.filter((job) => ["running", "queued", "paused"].includes(job.status));
  return { ...generation,
    score: { headline: score.headline, status: latestRunState("Evaluation", saved || evaluation, !generation.inputs || generation.inputs.state === "current"),
      attempt: saved && evaluation && saved.id !== evaluation.id ? `${scoringSummary(latest, evaluation, item, snapshot).headline} · Showing the previous saved score` : undefined },
    detail: [countLabel(jobs.length + imports.length, "run"), active.length && jobStatusCounts(active), imports.length && `${imports.length} imported`, latest && generation.detail].filter(Boolean).join(" · ") };
}

export type BundleEntry = { kind: "job"; id: string; time: number; job: StudioJob } | { kind: "import"; id: string; time: number; bundle: ImportedBundle };

export function orderedBundles(jobs: StudioJob[], imports: ImportedBundle[]): BundleEntry[] {
  return [...jobs.map((job) => ({ kind: "job" as const, id: job.id, time: jobSubmittedAt(job), job })),
    ...imports.map((bundle) => ({ kind: "import" as const, id: bundle.id, time: bundle.created_at, bundle }))]
    .sort((a, b) => b.time - a.time || a.id.localeCompare(b.id));
}

export function bundleSummary(jobs: StudioJob[], imports: ImportedBundle[], sizes: Record<string, number | null>): SectionSummary {
  const entries = orderedBundles(jobs, imports);
  const latest = entries[0];
  if (!latest) return { headline: "No bundles yet", detail: "No generated or imported data" };
  const complete = jobs.filter((job) => job.status === "completed").length + imports.length;
  const totals = `${countLabel(entries.length, "bundle")} · ${complete} complete${entries.length > complete ? ` · ${entries.length - complete} incomplete` : ""}`;
  if (latest.kind === "import") return { headline: `Completed · ${formatBundleSize(latest.bundle.size_bytes)} · Imported`, detail: `Latest bundle #${latest.id.slice(0, 8)} · ${formatTime(latest.time)} · ${totals}` };
  const size = sizes[latest.id];
  return { headline: `${latest.job.status[0].toUpperCase() + latest.job.status.slice(1)} · ${size == null ? latest.job.status === "queued" ? "Bundle pending" : "Size unavailable" : `${latest.job.status === "completed" ? "" : "Partial data "}${formatBundleSize(size)}`}`,
    detail: `Latest run #${latest.id.slice(0, 8)} · ${latest.time ? formatTime(latest.time) : "Time unknown"} · ${totals}` };
}

export function validationSummary(result: ValidationResult | undefined, stale: boolean, completedAt?: number): SectionSummary {
  if (!result) return { headline: "Not validated", detail: "No saved validation results" };
  const report = result.report;
  const issues = Array.isArray(report?.issues) ? report.issues as { severity?: string }[] : [];
  const counts = report?.severity_counts as Record<string, number> | undefined;
  const errors = counts?.error ?? issues.filter((issue) => issue.severity === "error").length;
  const warnings = counts?.warning ?? issues.filter((issue) => issue.severity === "warning").length;
  const infos = counts?.info ?? issues.filter((issue) => issue.severity === "info").length;
  const others = Math.max(0, issues.length - errors - warnings - infos);
  const findings = [errors > 0 && countLabel(errors, "error"), warnings > 0 && countLabel(warnings, "warning"), infos > 0 && countLabel(infos, "info finding"), others > 0 && countLabel(others, "other finding")].filter(Boolean).join(" · ");
  const valid = result.exit_code === 0 && report?.valid !== false && errors === 0;
  return { headline: !report ? "Validation could not finish" : `${valid ? warnings ? "Valid with warnings" : "Passed" : "Needs changes"}${findings ? ` · ${findings}` : valid ? " · No validation issues found" : ""}`,
    detail: [stale ? "Out of date · revalidate current inputs" : "Current revision", completedAt ? `Checked ${formatTime(completedAt)}` : ""].filter(Boolean).join(" · ") };
}

export function environmentSummary(health: DependencyHealth | undefined): SectionSummary {
  if (!health) return { headline: "Dependencies not checked", detail: "Expand to inspect packs and configuration" };
  const packs = health.rows.filter((row) => row.kind === "pack");
  const includes = health.rows.filter((row) => row.kind === "include");
  const overlays = health.rows.filter((row) => row.kind === "overlay");
  const problems = health.rows.filter((row) => ["missing", "conflict"].includes(row.status));
  const warnings = health.rows.filter((row) => row.status === "warning");
  return { headline: [health.ready ? "Dependencies ready" : `${countLabel(problems.length, "dependency error")}`, packs.length ? countLabel(packs.length, "pack") : "Inline environment", includes.length && countLabel(includes.length, "include"), overlays.length && countLabel(overlays.length, "overlay"), warnings.length && countLabel(warnings.length, "warning")].filter(Boolean).join(" · "),
    detail: (problems.length ? problems : packs).slice(0, 2).map((row) => row.label).join(" · ") + ((problems.length || packs.length) > 2 ? ` · ${(problems.length || packs.length) - 2} more` : "") || "No pack dependencies" };
}
