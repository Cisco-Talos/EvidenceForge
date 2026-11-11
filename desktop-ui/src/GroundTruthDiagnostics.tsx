import { useState } from "react";
import { CheckCircle2, ChevronDown, CircleMinus, Link2, Search, TriangleAlert, XCircle } from "lucide-react";
import { Help } from "./Help";
import { actionLabel, diagnosticCategories, groupDiagnostics, ruleLabel, type GroundTruthSummary } from "./groundTruthFindings";

const scoringHelp = "Each authored action has equal weight. Within an action, each required source projection is one check. Several diagnostic messages can describe the same defective check; they are counted once in that action’s score. The overall agreement score averages the action scores. The minimum and verdict come from the saved evaluation.";
const coverageHelp = "Valid expected absences do not add successes or failures. Coverage gaps describe missing source families. Legitimate actions with zero applicable checks score 100%; missing or invalid contracts cannot qualify as legitimate zero-check actions.";

function countLabel(value: number, unit: string): string {
  return `${value.toLocaleString()} ${unit}${value === 1 ? "" : "s"}`;
}

export function GroundTruthDiagnostics({ agreement, minimum = 95 }: { agreement: GroundTruthSummary; minimum?: number }) {
  const [search, setSearch] = useState("");
  const groups = groupDiagnostics(agreement.findings);
  const messageTotal = agreement.total_findings ?? agreement.findings.length;
  const truncated = agreement.findings_truncated === true || messageTotal > agreement.findings.length;
  const completeGroups = !truncated && groups.length === agreement.incorrect;
  const needle = search.trim().toLocaleLowerCase();
  const visible = groups.filter((group) => {
    const category = diagnosticCategories.find((item) => item.id === group.category)!;
    const text = [category.label, category.description, ...group.findings.map((finding) => ruleLabel(finding.rule)), JSON.stringify(group)].join(" ");
    return !needle || text.toLocaleLowerCase().includes(needle);
  });
  const tone = agreement.score < minimum ? "failed" : agreement.incorrect || agreement.score < 100 ? "marginal" : "passed";
  const VerdictIcon = tone === "failed" ? XCircle : tone === "marginal" ? TriangleAlert : CheckCircle2;

  return <details className="scorecard-sources ground-truth-diagnostics">
    <summary className="ground-truth-heading">
      <strong>Ground truth</strong>
      <span className={`ground-truth-status subscore-${tone}`}><VerdictIcon size={15} aria-hidden="true" />{agreement.score.toFixed(2)}% · {agreement.score >= minimum ? "Pass" : "Below minimum"}</span>
      <span className="ground-truth-totals">{countLabel(agreement.incorrect, "defective check")} · {countLabel(messageTotal, "diagnostic message")}</span>
      <ChevronDown className="ground-truth-chevron" size={14} aria-hidden="true" />
    </summary>
    <div className="ground-truth-body">
      <div className="ground-truth-explanation"><span>Minimum {minimum}% · {agreement.correct.toLocaleString()} correct / {(agreement.correct + agreement.incorrect).toLocaleString()} checks across {agreement.actions_count.toLocaleString()} equally weighted actions.</span><Help text={scoringHelp} /></div>
      <div className="ground-truth-explanation muted small"><span>{agreement.expected_absences.toLocaleString()} expected absences · {agreement.coverage_gaps.toLocaleString()} coverage gaps · {agreement.zero_check_actions.toLocaleString()} legitimate zero-check actions.</span><Help text={coverageHelp} /></div>
      {(agreement.verification_limitations || []).length > 0 && <div className="ground-truth-limitations"><TriangleAlert className="subscore-marginal" size={16} aria-hidden="true" /><div><strong>Verification limitations in this bundle</strong>{agreement.verification_limitations?.map((limitation) => <p key={limitation}>{limitation}</p>)}</div></div>}
      {truncated && <p className="ground-truth-truncation" role="note"><TriangleAlert size={15} aria-hidden="true" />Showing {agreement.findings.length} of {messageTotal} diagnostic messages. Additional findings are omitted. Categories and search cover these saved examples; complete totals above remain unchanged.</p>}
      {agreement.findings.length > 0 ? <>
        <div role="search" aria-label="Search ground truth diagnostics">
          <label className="ground-truth-search">Search<Search size={14} aria-hidden="true" /><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Action, occurrence, source or evidence…" /></label>
        </div>
        <div className="ground-truth-filter-summary" role="status"><span>Showing {visible.length} of {countLabel(groups.length, completeGroups ? "defective check" : "displayed check group")} · {countLabel(visible.reduce((total, group) => total + group.findings.length, 0), "diagnostic message")}.</span>{search && <button className="button-quiet" onClick={() => setSearch("")}>Clear search</button>}</div>
        {agreement.findings.some((finding) => !finding.check_id) && <div className="ground-truth-explanation muted small"><span>Earlier report: grouped using available identities.</span><Help text="This report predates exact diagnostic check IDs. Source messages are grouped by action, occurrence, source and format. Action-level semantic messages are grouped by their known scoring family. Re-evaluate to capture exact check IDs; the saved score is unchanged." /></div>}
        {visible.length === 0 && <p>No diagnostics match this search.</p>}
        {diagnosticCategories.map((item) => {
          const members = visible.filter((group) => group.category === item.id);
          if (!members.length) return null;
          const Icon = item.id === "relationships" ? Link2 : item.tone === "failed" ? XCircle : item.tone === "marginal" ? TriangleAlert : CircleMinus;
          return <section key={item.id} className="ground-truth-category" aria-label={item.label}>
            <details className="ground-truth-category-disclosure">
              <summary>
                <div className="ground-truth-category-heading"><Icon className={`subscore-${item.tone}`} size={17} aria-hidden="true" /><h4>{item.label}</h4><span>{countLabel(members.length, completeGroups ? "check" : "shown group")} · {countLabel(members.reduce((total, group) => total + group.findings.length, 0), "message")}</span><Help text={item.help} /><ChevronDown className="ground-truth-chevron" size={14} aria-hidden="true" /></div>
                <p className="ground-truth-category-description muted small">{item.description}</p>
              </summary>
              <div className="ground-truth-category-body">
            {members.map((group) => {
              const finding = group.findings[0];
              const title = item.id === "metadata" ? ruleLabel(group.findings.find((message) => message.rule.startsWith("missing_"))?.rule || finding.rule) : ruleLabel(finding.rule);
              return <details key={group.id} className="ground-truth-check">
                <summary><Icon className={`subscore-${item.tone}`} size={15} aria-hidden="true" /><span><strong>{actionLabel(finding)}</strong><small>{group.source}{finding.format ? ` · ${finding.format}` : ""} · {title}{finding.occurrence_id ? ` · occurrence ${finding.occurrence_id.slice(0, 8)}` : ""}</small></span><span className="ground-truth-message-count">{group.findings.length} {group.findings.length === 1 ? "message" : "messages"}</span><ChevronDown size={14} className="ground-truth-chevron" aria-hidden="true" /></summary>
                <div className="ground-truth-check-body"><p className="muted small">Action {finding.intent_id} · occurrence {finding.occurrence_id || "action-level check"}</p>
                  {group.findings.map((message, index) => <details className="ground-truth-message" key={`${message.rule}-${index}`}><summary>{ruleLabel(message.rule)}<code>{message.rule}</code></summary><pre>{JSON.stringify(message.details ?? "No additional details were captured.", null, 2)}</pre></details>)}
                </div>
              </details>;
            })}
              </div>
            </details>
          </section>;
        })}
      </> : <p>{agreement.incorrect ? "No representative messages were captured in this report. Re-evaluate to obtain diagnostics." : "No ground-truth disagreements were reported."}</p>}
    </div>
  </details>;
}
