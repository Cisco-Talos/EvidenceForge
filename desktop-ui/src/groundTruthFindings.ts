export type GroundTruthFinding = {
  check_id?: string | null;
  intent_id: string;
  storyline_id?: string | null;
  occurrence_id?: string | null;
  source_instance?: string | null;
  format?: string | null;
  rule: string;
  details?: unknown;
};

export type GroundTruthSummary = {
  score: number;
  correct: number;
  incorrect: number;
  actions_count: number;
  zero_check_actions: number;
  expected_absences: number;
  coverage_gaps: number;
  total_findings?: number;
  displayed_findings?: number;
  findings_truncated?: boolean;
  verification_limitations?: string[];
  findings: GroundTruthFinding[];
};

export const diagnosticCategories = [
  { id: "metadata", label: "Missing verification metadata", tone: "marginal", description: "Required proof was not captured.", help: "These checks need provenance that is absent from the bundle. Re-evaluation cannot reconstruct metadata that was never captured. Regenerate with the current engine; if a fresh run still lacks it, investigate metadata capture. These checks remain included in the saved score." },
  { id: "evidence", label: "Evidence disagreement", tone: "failed", description: "Evidence is missing, duplicated or differs from required facts.", help: "Inspect the required facts, matching counts and evidence locations. This category identifies a disagreement, not whether the generator, ground truth or evaluator caused it. Correct the owning defect and regenerate when the original evidence or truth must change." },
  { id: "relationships", label: "Relationship verification", tone: "marginal", description: "A canonical relationship could not be validated.", help: "Inspect the relationship rules and occurrence identities. A failed relationship check can require further investigation, such as missing DNS cache-consumption provenance. This category does not establish the underlying cause." },
  { id: "timing", label: "Timing disagreement", tone: "failed", description: "Recorded timing does not satisfy the required bounds or dependencies.", help: "Compare source timestamps with canonical times, timing anchors and permitted gaps. Matching truth and log timestamps alone does not establish correct ordering. A check also reporting missing proof appears in Missing verification metadata." },
  { id: "contract", label: "Contract or expectation problems", tone: "failed", description: "An expectation or its justification could not be validated.", help: "Review the engine-owned evidence contract and captured source policy. Missing expectations, unsupported contracts and unjustified exclusions remain defects. Do not change scenario settings merely to conceal an invalid contract." },
  { id: "other", label: "Other diagnostics", tone: "unrated", description: "These rules need individual review.", help: "The saved rule is not assigned a more specific category by this Studio version. Expand the message for the rule and recorded details; its scoring is unchanged." },
] as const;

export type DiagnosticCategory = typeof diagnosticCategories[number]["id"];
export type DiagnosticGroup = {
  id: string;
  action: string;
  source: string;
  category: DiagnosticCategory;
  findings: GroundTruthFinding[];
};

const evidenceRules = new Set(["factual_disagreement", "missing_evidence", "missing_or_duplicate_evidence", "unexpected_evidence", "raw_evidence_disagreement", "missing_canonical_occurrence", "missing_required_consequence", "missing_process_network_consequence", "missing_authored_http_consequence", "missing_required_storage_consequence"]);
const timingRules = new Set(["timing_disagreement", "unjustified_source_time", "invalid_timing_dependency_order", "invalid_timing_dependency_identity", "process_timing_identity_disagreement", "invalid_process_timing_provenance", "unverifiable_timing_dependency"]);
const contractRules = new Set(["unknown_intent", "missing_source_expectation", "duplicate_source_expectation", "missing_coverage_gap", "unaccounted_source_coverage", "fabricated_coverage_gap", "unexpected_source_expectation", "unknown_source_identity", "incorrect_phase", "incorrect_leg_or_transaction_phase", "incorrect_projection_identity", "incomplete_decision_stages", "empty_evidence_contract", "unverifiable_projection_contract", "source_identifier_disagreement", "capture_profile_identity_disagreement"]);

function categoryFor(findings: GroundTruthFinding[]): DiagnosticCategory {
  const rules = findings.map((finding) => finding.rule);
  if (rules.some((rule) => rule === "missing_process_timing_provenance" || rule === "missing_loss_provenance" || rule === "missing_native_dns_identity")) return "metadata";
  if (rules.includes("canonical_relationship_disagreement")) return "relationships";
  if (rules.some((rule) => contractRules.has(rule) || /contract|^invalid_(?:absence|.*decision)|^unjustified_.*exclusion|^loss_/.test(rule))) return "contract";
  if (rules.some((rule) => evidenceRules.has(rule) || rule.startsWith("authored_"))) return "evidence";
  if (rules.some((rule) => timingRules.has(rule))) return "timing";
  return "other";
}

function legacyCheckIdentity(finding: GroundTruthFinding): string {
  if (finding.source_instance) return JSON.stringify([finding.intent_id, finding.occurrence_id, finding.source_instance, finding.format]);
  // Older reports lack exact check IDs. Only the known action-level semantic
  // family shares one scored check; independent canonical rules stay separate.
  const semantic = finding.rule.startsWith("authored_") || ["unsupported_authored_contract", "missing_authored_http_consequence", "missing_required_storage_consequence"].includes(finding.rule);
  return JSON.stringify([finding.intent_id, finding.occurrence_id, semantic ? "typed-facts" : finding.rule, semantic ? null : finding.details]);
}

export function groupDiagnostics(findings: GroundTruthFinding[]): DiagnosticGroup[] {
  const groups = new Map<string, GroundTruthFinding[]>();
  for (const finding of findings) {
    const id = finding.check_id || legacyCheckIdentity(finding);
    const messages = groups.get(id) || [];
    messages.push(finding);
    groups.set(id, messages);
  }
  return Array.from(groups, ([id, messages]) => ({ id, action: messages[0].intent_id, source: messages[0].source_instance || "Canonical truth", category: categoryFor(messages), findings: messages }));
}

export function actionLabel(finding: GroundTruthFinding): string {
  return finding.storyline_id ? `${finding.storyline_id} · ${finding.intent_id.slice(0, 8)}` : finding.intent_id;
}

export function ruleLabel(rule: string): string {
  const labels: Record<string, string> = {
    missing_process_timing_provenance: "Timing proof is missing",
    unjustified_source_time: "Source time could not be justified",
    missing_or_duplicate_evidence: "Evidence count does not match",
    missing_evidence: "Expected evidence is missing",
    factual_disagreement: "Required facts do not match",
    canonical_relationship_disagreement: "Canonical relationship could not be validated",
  };
  return labels[rule] || rule.replace(/_/g, " ").replace(/^./, (letter) => letter.toUpperCase());
}
