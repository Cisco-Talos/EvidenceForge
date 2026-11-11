import { afterEach, expect, test, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScorecardPanel } from "../src/ScorecardPanel";
import { groupDiagnostics, type GroundTruthSummary } from "../src/groundTruthFindings";
import type { StudioApi } from "../src/api";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const report = { scenario_name: "Source agreement", evaluated_at: "2026-11-10T13:00:00Z", overall_score: 99, acceptance_passed: true, total_records: 100, pillars: [{ name: "Ground Truth Agreement", score: 99.29, sub_scores: [] }], flags: [], acceptance_criteria: [], source_counts: {} };
const findings = [
  { check_id: "timing-check", intent_id: "action-1", storyline_id: "discovery", occurrence_id: "process-exec", source_instance: "ecar:mac-02", format: "ecar", rule: "missing_process_timing_provenance", details: { expected: "timing proof" } },
  { check_id: "timing-check", intent_id: "action-1", storyline_id: "discovery", occurrence_id: "process-exec", source_instance: "ecar:mac-02", format: "ecar", rule: "unjustified_source_time", details: { expected: "bounded delay" } },
  { check_id: "scan-check", intent_id: "action-2", storyline_id: "scan", occurrence_id: "connection", source_instance: "asa:gateway", format: "cisco_asa", rule: "missing_evidence", details: { actual: [], path: "gateway/asa.log" } },
  { check_id: "scan-check", intent_id: "action-2", storyline_id: "scan", occurrence_id: "connection", source_instance: "asa:gateway", format: "cisco_asa", rule: "missing_or_duplicate_evidence", details: { selected_count: 0 } },
  { check_id: "dns-check", intent_id: "action-1", storyline_id: "discovery", rule: "canonical_relationship_disagreement", details: [{ rules: ["invalid_dns_cache_provenance"] }] },
];
const agreement: GroundTruthSummary = { score: 99.29, correct: 97, incorrect: 3, actions_count: 20, zero_check_actions: 2, expected_absences: 3, coverage_gaps: 4, total_findings: 5, findings };

function show(value: GroundTruthSummary = agreement, extra = {}) {
  const api = { request: vi.fn(async () => ({ ...report, ground_truth_agreement: value, ...extra })) } as unknown as StudioApi;
  return render(<ScorecardPanel jobId="saved" api={api} />);
}

async function openGroundTruth() {
  await userEvent.click(await screen.findByText("Ground truth"));
}

test("ground truth follows scores with precise score, distinct counts and colored verdict", async () => {
  const { container } = show();
  const heading = await screen.findByText("Ground truth");
  expect(container.querySelector(".scorecard-pillars")!.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(screen.getByText("99.29/100")).toBeInTheDocument();
  expect(screen.getByText("99.29% · Pass")).toHaveClass("subscore-marginal");
  expect(screen.getByText("3 defective checks · 5 diagnostic messages")).toBeVisible();
  await openGroundTruth();
  expect(screen.getByText(/97 correct \/ 100 checks across 20 equally weighted actions/)).toBeVisible();
  expect(screen.getByText(/3 expected absences · 4 coverage gaps · 2 legitimate zero-check actions/)).toBeVisible();
  expect(screen.getByText("Showing 3 of 3 defective checks · 5 diagnostic messages.")).toBeVisible();
});

test("categories start collapsed with visible summaries and drill down to checks and messages", async () => {
  show(); await openGroundTruth();
  const metadata = screen.getByRole("region", { name: "Missing verification metadata" });
  const evidence = screen.getByRole("region", { name: "Evidence disagreement" });
  const relationships = screen.getByRole("region", { name: "Relationship verification" });
  for (const category of [metadata, evidence, relationships]) {
    expect(category.querySelector(".ground-truth-category-disclosure")).not.toHaveAttribute("open");
  }
  expect(within(metadata).getByText("1 check · 2 messages")).toBeVisible();
  expect(within(metadata).getByText("Required proof was not captured.")).toBeVisible();
  expect(within(metadata).getByRole("button", { name: /^These checks need provenance/ })).toBeVisible();
  expect(metadata.querySelectorAll(".ground-truth-check")).toHaveLength(1);
  expect(within(metadata).getByText("discovery · action-1")).not.toBeVisible();
  await userEvent.click(within(metadata).getByText("Missing verification metadata"));
  expect(categoryDisclosure(metadata).open).toBe(true);
  expect(categoryDisclosure(evidence).open).toBe(false);
  expect(within(metadata).getByText("discovery · action-1")).toBeVisible();
  expect(within(metadata).getByText(/Action action-1 · occurrence process-exec/)).not.toBeVisible();
  await userEvent.click(within(metadata).getByText("discovery · action-1"));
  expect(within(metadata).getByText(/Action action-1 · occurrence process-exec/)).toBeVisible();
  await userEvent.click(within(metadata).getByText("Timing proof is missing"));
  expect(within(metadata).getByText(/"expected": "timing proof"/)).toBeVisible();
  expect(within(metadata).getByText("Source time could not be justified")).toBeVisible();
  expect(screen.getByRole("region", { name: "Evidence disagreement" })).toBeVisible();
  expect(screen.getByRole("region", { name: "Relationship verification" })).toBeVisible();
  await userEvent.click(within(metadata).getByText("Missing verification metadata"));
  expect(within(metadata).getByText(/"expected": "timing proof"/)).not.toBeVisible();
});

function categoryDisclosure(category: HTMLElement): HTMLDetailsElement {
  return category.querySelector(".ground-truth-category-disclosure") as HTMLDetailsElement;
}

test("search replaces dropdown filters and matches categories, actions, sources, rules and evidence", async () => {
  show(); await openGroundTruth();
  const user = userEvent.setup();
  expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  await user.type(screen.getByLabelText("Search"), "Missing verification metadata");
  expect(screen.getByText("Showing 1 of 3 defective checks · 2 diagnostic messages.")).toBeVisible();
  expect(categoryDisclosure(screen.getByRole("region", { name: "Missing verification metadata" })).open).toBe(false);
  await user.click(screen.getByRole("button", { name: "Clear search" }));
  await user.type(screen.getByLabelText("Search"), "unknown-host");
  expect(screen.getByText("No diagnostics match this search.")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Clear search" }));
  await user.type(screen.getByLabelText("Search"), "gateway/asa.log");
  expect(screen.getByText("Showing 1 of 3 defective checks · 2 diagnostic messages.")).toBeVisible();
  for (const query of ["ECAR:MAC-02", "unjustified_source_time", "Source time could not be justified", "process-exec"]) {
    await user.clear(screen.getByLabelText("Search"));
    await user.type(screen.getByLabelText("Search"), query);
    expect(screen.getByText("Showing 1 of 3 defective checks · 2 diagnostic messages.")).toBeVisible();
  }
  await user.clear(screen.getByLabelText("Search"));
  await user.type(screen.getByLabelText("Search"), "action-1");
  expect(screen.getByText("Showing 2 of 3 defective checks · 3 diagnostic messages.")).toBeVisible();
  expect(screen.queryByRole("region", { name: "Evidence disagreement" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Clear search" }));
  expect(screen.getByText("Showing 3 of 3 defective checks · 5 diagnostic messages.")).toBeVisible();
});

test("bounded examples keep full totals and disclose partial category coverage", async () => {
  show({ ...agreement, incorrect: 4, total_findings: 8, displayed_findings: 1, findings_truncated: true, verification_limitations: ["Regenerate to capture process timing dependencies."], findings: [findings[0]] });
  await openGroundTruth();
  expect(screen.getByText("4 defective checks · 8 diagnostic messages")).toBeVisible();
  expect(screen.getByText(/Showing 1 of 8 diagnostic messages. Additional findings are omitted/)).toBeVisible();
  expect(screen.getByText("Showing 1 of 1 displayed check group · 1 diagnostic message.")).toBeVisible();
  expect(screen.getByText("Regenerate to capture process timing dependencies.")).toBeVisible();
});

test("older reports group available identities and retain independent canonical checks", async () => {
  const old = findings.map(({ check_id: _checkId, ...finding }) => finding);
  expect(groupDiagnostics(old)).toHaveLength(3);
  show({ ...agreement, findings: old, total_findings: undefined });
  await openGroundTruth();
  expect(screen.getByText("Earlier report: grouped using available identities.")).toBeVisible();
  expect(groupDiagnostics([
    { intent_id: "action", rule: "missing_canonical_occurrence" },
    { intent_id: "action", rule: "canonical_relationship_disagreement" },
    { intent_id: "action", rule: "authored_typed_facts_disagreement" },
    { intent_id: "action", rule: "authored_http_status_disagreement" },
  ])).toHaveLength(3);
});

test("exact check IDs distinguish projections sharing occurrence and source", () => {
  expect(groupDiagnostics([findings[0], { ...findings[0], check_id: "different-projection" }])).toHaveLength(2);
});

test("existing help icon explains scoring on keyboard focus", async () => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  show(); await openGroundTruth();
  screen.getByRole("button", { name: /^Each authored action has equal weight/ }).focus();
  expect(await screen.findByRole("tooltip")).toHaveTextContent("Several diagnostic messages can describe the same defective check");
});

test("complete agreement and saved custom minimum get appropriate verdicts", async () => {
  show({ ...agreement, score: 100, incorrect: 0, findings: [], total_findings: 0 });
  await openGroundTruth();
  expect(screen.getByText("100.00% · Pass")).toHaveClass("subscore-passed");
  expect(screen.getByText("No ground-truth disagreements were reported.")).toBeVisible();
  cleanup();
  show({ ...agreement, score: 94.99 }, { acceptance_criteria: [{ name: "ground_truth.ground_truth_agreement", threshold: 96, level: "hard", passed: false, actual: 94.99 }] });
  await openGroundTruth();
  expect(screen.getByText("94.99% · Below minimum")).toHaveClass("subscore-failed");
  expect(screen.getByText(/Minimum 96%/)).toBeVisible();
});

test("legacy scorecard states missing agreement coverage", async () => {
  const api = { request: vi.fn(async () => ({ ...report, ground_truth_coverage: { schema_version: 4 } })) } as unknown as StudioApi;
  render(<ScorecardPanel jobId="legacy" api={api} />);
  expect(await screen.findByText(/Legacy ground-truth coverage: source expectations are unavailable/)).toBeVisible();
  expect(screen.queryByText("Ground truth")).not.toBeInTheDocument();
});
