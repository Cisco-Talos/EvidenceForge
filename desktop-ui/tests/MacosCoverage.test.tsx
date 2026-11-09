import { afterEach, expect, test, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScorecardPanel } from "../src/ScorecardPanel";
import type { StudioApi } from "../src/api";

afterEach(cleanup);

test("native coverage separates complete starts, unknown exits and historical measurements", async () => {
  const census = { complete: true, expected_forks: 3, published_forks: 3, expected_execs: 4, published_execs: 4, observed_exits: 3, known_exits: 2, published_exits: 2, exit_complete: false };
  const api = { request: vi.fn(async () => ({ scenario_name: "Mac", evaluated_at: "2026-11-06T13:00:00Z", overall_score: 96, acceptance_passed: true, total_records: 100, pillars: [], flags: [], acceptance_criteria: [], source_counts: {}, macos_hosts: [
    { hostname: "MAC", source_profile: "invented", policy: "partial", census },
    { hostname: "OLD", source_profile: "historical", policy: "complete", census: { ...census, observed_exits: null, known_exits: null, published_exits: null, exit_complete: null } },
  ] })) } as unknown as StudioApi;
  render(<ScorecardPanel jobId="saved" api={api} />);
  await userEvent.click(await screen.findByText("macOS process coverage"));
  expect(screen.getByText(/Partial collection/)).toBeVisible();
  expect(screen.getAllByText(/Process starts complete/)).toHaveLength(2);
  expect(screen.getByText(/Exits incomplete/)).toHaveClass("score-fail");
  expect(screen.getByText(/Exit completeness unmeasured/)).toHaveClass("score-indeterminate");
  expect(screen.getByText("2 / 2")).toBeVisible();
  expect(screen.getByText("Unmeasured / Unmeasured")).toBeVisible();
  expect(screen.getByText("Acceptance passed")).toBeVisible();
});
