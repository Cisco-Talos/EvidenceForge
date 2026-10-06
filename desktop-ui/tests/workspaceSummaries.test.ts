import { generationInputs, generationIsCurrent } from "../src/ScenarioStates";
import { expect, test } from "vitest";
import type { CatalogItem, ImportedBundle, StudioJob, StudioSnapshot } from "../src/api";
import { bundleSummary, generationSummary, latestJob, latestRunState, orderedBundles, runsSummary, scoringSummary, validationSummary } from "../src/workspaceSummaries";

const item = { id: "scenario", path: "/workspace/scenario.yaml", source_sha256: "current" } as CatalogItem;
const snapshot = { dependencies: { scenario: { fingerprint: "packs", changed_at: 10 } } } as StudioSnapshot;
const run: StudioJob = { id: "old-run", kind: "generation", status: "completed", status_message: "", scenario: item.path, output_root: "/workspace/runs/old", submitted_at: 20, started_at: 100, source_sha256: "current", dependency_sha256: "packs", can_resume: false };

test("latest submission stays the summary target when an older run resumes later", () => {
  const newer = { ...run, id: "new-run", submitted_at: 30, started_at: 30, status: "failed" };
  expect(latestJob([newer, run])?.id).toBe("new-run");
  const summary = generationSummary(latestJob([newer, run]), item, snapshot, 1024);
  expect(summary.headline).toBe("Failed · Partial data 1.0 KB");
  expect(summary.detail).toContain("Latest run #new-run");
});

test("equal timestamps and missing legacy dates use the same tie order for rows and header", () => {
  const a = { ...run, id: "a", submitted_at: 20 };
  const z = { ...run, id: "z", submitted_at: 20 };
  expect(orderedBundles([z, a], [])[0].id).toBe(latestJob([z, a])?.id);
  expect(latestJob([z, a])?.id).toBe("a");
  const unknown = [z, a].map((job) => ({ ...job, submitted_at: undefined, started_at: undefined }));
  expect(orderedBundles(unknown, [])[0].id).toBe(latestJob(unknown)?.id);
});

test("merged runs summary keeps generation, score, counts and input freshness together", () => {
  const evaluation: StudioJob = { ...run, id: "score", kind: "evaluation", generation_id: run.id, created_at: 25, scorecard: { overall_score: 96, acceptance_passed: false } };
  const older = { ...run, id: "older", status: "paused", submitted_at: 15 };
  const imported = { id: "imported", created_at: 30, size_bytes: 2048 } as ImportedBundle;
  const summary = runsSummary([run, older], [imported], [evaluation], item, snapshot, { "old-run": 1024 });
  expect(summary.headline).toBe("Completed · Generated data 1.0 KB");
  expect(summary.score?.headline).toBe("96/100 · Failed");
  expect(summary.score?.status.state).toBe("error");
  expect(summary.detail).toContain("3 runs · 1 paused · 1 imported");
  expect(summary.detail).toContain("Latest run #old-run");
  expect(summary.inputs?.state).toBe("current");
  expect(runsSummary([{ ...run, id: "new", submitted_at: 40 }], [], [evaluation], item, snapshot, {}).score?.headline).toBe("Not evaluated");
  expect(runsSummary([], [imported], [], item, snapshot, {}).headline).toBe("Completed · 2.0 KB · Imported");
  expect(runsSummary([], [], [], item, snapshot, {}, 1024).headline).toBe("Estimated data 1.0 KB");
});

test.each([
  { generation: { ...run, dependency_sha256: undefined, submitted_at: 5 }, state: "unverified", label: "Inputs unverified" },
  { generation: { ...run, source_sha256: "previous" }, state: "changed", label: "Inputs changed" },
])("the latest run's score and $label remain together in its header summary", ({ generation, state, label }) => {
  const evaluation: StudioJob = { ...run, id: "score", kind: "evaluation", generation_id: generation.id, created_at: 25, scorecard: { overall_score: 96, acceptance_passed: false, total_records: 121793 } };
  const summary = runsSummary([generation], [], [evaluation], item, snapshot, {});
  expect(summary.score?.headline).toBe("96/100 · Failed · 121,793 records");
  expect(summary.score?.status.state).toBe("error");
  expect(summary.inputs).toMatchObject({ state, label });
});

test.each(["running", "failed", "completed"])("a %s retry without a readable report keeps the latest run's saved score in the header", (status) => {
  const saved: StudioJob = { ...run, kind: "evaluation", id: "saved", generation_id: run.id, created_at: 21, scorecard: { overall_score: 96, acceptance_passed: false } };
  const retry = { ...saved, id: "retry", submitted_at: undefined, created_at: 30, status, scorecard: status === "completed" ? { error: "Unreadable report" } : undefined };
  const summary = runsSummary([run], [], [saved, retry], item, snapshot, {});
  expect(summary.score?.headline).toBe("96/100 · Failed");
  expect(summary.score?.attempt).toContain("Showing the previous saved score");
  expect(summary.score?.attempt).toContain(status === "completed" ? "Score report unavailable" : `Evaluation ${status}`);
  const replacement = { ...retry, status: "completed", scorecard: { overall_score: 91, acceptance_passed: false } };
  const replaced = runsSummary([run], [], [saved, replacement], item, snapshot, {});
  expect(replaced.score?.headline).toBe("91/100 · Failed");
  expect(replaced.score?.attempt).toBeUndefined();
});

test("an actual completed size is separate from the estimate for changed inputs", () => {
  const summary = generationSummary({ ...run, dependency_sha256: "previous-packs" }, item, snapshot, 2097152, 4194304);
  expect(summary.headline).toBe("Completed · Generated data 2.0 MB");
  expect(summary.inputs?.state).toBe("changed");
  expect(summary.inputs?.label).toBe("Inputs changed");
  expect(summary.detail).toContain("Current estimate 4.0 MB");
});

test("paused generation keeps its simulated-hour progress and measured partial size", () => {
  const summary = generationSummary({ ...run, status: "paused", progress: { phase: "Generating", completed_hours: 6, total_hours: 24 } }, item, snapshot, 1536, 10000);
  expect(summary.headline).toBe("Paused · 6 of 24 simulated hours · 25% · Partial data 1.5 KB");
  expect(summary.detail).toContain("Current revision");
});

test.each([
  { status: "queued", scorecard: undefined, headline: "Evaluation queued" },
  { status: "running", scorecard: undefined, headline: "Evaluation running" },
  { status: "failed", scorecard: undefined, headline: "Evaluation failed" },
  { status: "completed", scorecard: { overall_score: 92, acceptance_passed: false }, headline: "92/100 · Failed" },
  { status: "completed", scorecard: { overall_score: 90, acceptance_passed: null }, headline: "90/100 · Indeterminate" },
  { status: "completed", scorecard: { error: "Unreadable report" }, headline: "Score report unavailable" },
])("evaluation summary describes $headline", ({ status, scorecard, headline }) => {
  const evaluation: StudioJob = { ...run, id: "score", kind: "evaluation", generation_id: run.id, status, scorecard };
  expect(scoringSummary(run, evaluation, item, snapshot).headline).toBe(headline);
});

test("bundles use submission order across owned and imported data with a deterministic tie", () => {
  const imported = { id: "import", root: "/external/bundle", created_at: 30, size_bytes: 3072 } as ImportedBundle;
  const queued = { ...run, id: "queued", status: "queued", submitted_at: 40 };
  expect(orderedBundles([queued, run], [imported]).map((entry) => entry.id)).toEqual(["queued", "import", "old-run"]);
  expect(bundleSummary([run], [imported], { "old-run": 1024 }).headline).toBe("Completed · 3.0 KB · Imported");
  expect(bundleSummary([queued, run], [imported], {}).headline).toBe("Queued · Bundle pending");
  expect(bundleSummary([queued, run], [imported], {}).detail).toContain("3 bundles · 2 complete · 1 incomplete");
  expect(orderedBundles([{ ...run, submitted_at: 30 }], [imported]).map((entry) => entry.id)).toEqual(["import", "old-run"]);
});

test("a stale validation keeps its actual findings without claiming current success", () => {
  const summary = validationSummary({ exit_code: 1, error: "", report: { valid: false, issues: [{ severity: "error" }, { severity: "warning" }, { severity: "warning" }] } }, true, 100);
  expect(summary.headline).toBe("Needs changes · 1 error · 2 warnings");
  expect(summary.detail).toContain("Out of date · revalidate current inputs");
});


test("a legacy run with matching YAML and a later dependency check has unverified inputs", () => {
  const legacy = { ...run, dependency_sha256: undefined, submitted_at: 5 };
  const inputs = generationInputs(legacy, item, snapshot);
  expect(inputs.state).toBe("unverified");
  expect(inputs.detail).toContain("scenario YAML still matches");
  expect(inputs.detail).toContain("no dependency fingerprint");
  expect(generationIsCurrent(legacy, item, snapshot)).toBe(false);
  expect(generationSummary(legacy, item, snapshot, 1024).inputs).toEqual(inputs);
  const evaluation: StudioJob = { ...run, kind: "evaluation", scorecard: { overall_score: 96, acceptance_passed: false } };
  expect(scoringSummary(legacy, evaluation, item, snapshot).inputs).toEqual(inputs);
  expect(latestRunState("Generation", legacy, false).state).toBe("success");
  expect(latestRunState("Evaluation", evaluation, false).state).toBe("error");
});

test("matching, changed, and missing input records remain distinct", () => {
  expect(generationInputs(run, item, snapshot).state).toBe("current");
  expect(generationInputs({ ...run, source_sha256: "previous" }, item, snapshot).state).toBe("changed");
  expect(generationInputs({ ...run, dependency_sha256: "previous" }, item, snapshot).state).toBe("changed");
  expect(generationInputs({ ...run, source_sha256: undefined }, item, snapshot).state).toBe("unverified");
  expect(generationInputs(run, item, { ...snapshot, dependencies: {} }).state).toBe("unverified");
});

test("a known input change keeps generation and evaluation outcomes independent", () => {
  const changed = { ...run, dependency_sha256: "previous" };
  expect(latestRunState("Generation", changed, false)).toMatchObject({ state: "success" });
  expect(latestRunState("Generation", changed, false).detail).not.toContain("this scenario revision");
  expect(latestRunState("Evaluation", { ...changed, kind: "evaluation", scorecard: { overall_score: 96, acceptance_passed: false } }, false).state).toBe("error");
  expect(latestRunState("Evaluation", { ...changed, kind: "evaluation", scorecard: { overall_score: 96, acceptance_passed: true } }, false).state).toBe("success");
  expect(latestRunState("Evaluation", { ...changed, kind: "evaluation", scorecard: { overall_score: 96, acceptance_passed: null } }, false).state).toBe("warning");
});
