import { expect, test } from "vitest";
import type { CatalogItem, StudioJob, StudioSnapshot } from "../src/api";
import { generationInputs, inputsNeedAttention, scenarioStates } from "../src/ScenarioStates";

const release = { id: "scenario", kind: "scenario", path: "/workspace/release/scenario.yaml", source_sha256: "release-bytes", version: "1.1.0" } as CatalogItem;
const base = { jobs: [], validations: {}, conversations: [], source_paths: { scenario: [release.path, "/workspace/draft/scenario.yaml"] }, dependencies: { scenario: { fingerprint: "release-deps", changed_at: 10 } } } as unknown as StudioSnapshot;
const run = (overrides: Partial<StudioJob>): StudioJob => ({
  id: "run", kind: "generation", status: "completed", status_message: "", scenario: "/workspace/draft/scenario.yaml",
  output_root: "/workspace/runs/run", submitted_at: 20, started_at: 20, source_sha256: "draft-bytes", dependency_sha256: "draft-deps", ...overrides,
}) as StudioJob;

test("a draft run with the release content is current", () => {
  const job = run({ scenario_source: { name: "s", status: "draft", content_identity: "same" } });
  const inputs = generationInputs(job, release, { ...base, content_identities: { scenario: "same" } });
  expect(inputs.state).toBe("current");
  expect(inputs.label).toBe("Current content");
});

test("a run of another release carries its version without a warning", () => {
  const job = run({ scenario_source: { name: "s", status: "published", version: "1.0.0", content_identity: "older" } });
  const inputs = generationInputs(job, release, { ...base, content_identities: { scenario: "newer" } });
  expect(inputs).toMatchObject({ state: "version", label: "v1.0.0" });
  expect(inputsNeedAttention(inputs)).toBe(false);
});

test("a draft run with different content is changed", () => {
  // Drafts are not versioned, so a differing draft run cannot be labeled by version.
  const job = run({ scenario_source: { name: "s", status: "draft", content_identity: "edited" } });
  const inputs = generationInputs(job, release, { ...base, content_identities: { scenario: "newer" } });
  expect(inputs.state).toBe("changed");
  expect(inputsNeedAttention(inputs)).toBe(true);
});

test("a run of the same release with changed inputs is changed", () => {
  const job = run({ scenario_source: { name: "s", status: "published", version: "1.1.0" } });
  expect(generationInputs(job, release, base).state).toBe("changed");
});

test("only older-release runs report Not run instead of Stale", () => {
  const job = run({ scenario_source: { name: "s", status: "published", version: "1.0.0", content_identity: "older" } });
  const [, generation, evaluation] = scenarioStates(release, { ...base, jobs: [job], content_identities: { scenario: "newer" } });
  expect(generation.state).toBe("none");
  expect(generation.detail).toContain("latest run is from v1.0.0");
  expect(evaluation.state).toBe("none");
});

test("a draft run with the release content counts as generated", () => {
  const job = run({ scenario_source: { name: "s", status: "draft", content_identity: "same" } });
  const [, generation] = scenarioStates(release, { ...base, jobs: [job], content_identities: { scenario: "same" } });
  expect(generation.state).toBe("success");
});
