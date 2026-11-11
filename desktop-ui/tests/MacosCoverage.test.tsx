import { afterEach, expect, test, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScorecardPanel } from "../src/ScorecardPanel";
import type { StudioApi } from "../src/api";

afterEach(cleanup);

test("native coverage remains in raw report and is omitted from scorecard", async () => {
  const census = { complete: true, expected_forks: 3, published_forks: 3, expected_execs: 4, published_execs: 4, observed_exits: 3, known_exits: 2, published_exits: 2, exit_complete: false };
  const api = { request: vi.fn(async () => ({ scenario_name: "Mac", evaluated_at: "2026-11-06T13:00:00Z", overall_score: 96, acceptance_passed: true, total_records: 100, pillars: [], flags: [], acceptance_criteria: [], source_counts: {}, macos_hosts: [
    { hostname: "MAC", source_profile: "invented", policy: "partial", census },
    { hostname: "OLD", source_profile: "historical", policy: "complete", census: { ...census, observed_exits: null, known_exits: null, published_exits: null, exit_complete: null } },
  ] })), readTextPreview: vi.fn(async () => ({ text: JSON.stringify({ macos_native_coverage: { census } }), truncated: false, binary: false })) } as unknown as StudioApi;
  render(<ScorecardPanel jobId="saved" api={api} />);
  expect(await screen.findByText("Acceptance passed")).toBeVisible();
  expect(screen.queryByText("macOS process coverage")).not.toBeInTheDocument();
  expect(screen.queryByText(/Process starts complete/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "View raw report" }));
  expect(await screen.findByText(/macos_native_coverage/)).toBeVisible();
});
