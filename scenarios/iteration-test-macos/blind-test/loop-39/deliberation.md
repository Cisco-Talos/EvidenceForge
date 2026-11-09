# Deliberation Summary

**Status: FACILITATOR-MODELED.** This document synthesizes the four submitted independent reports. The experts were not reconvened, did not exchange messages, and did not cast revised votes. All final positions, confidence changes, and cross-examination responses below are facilitator-modeled interpretations of the supplied reports, not statements actually made by those experts. Only `deliberation-instructions.md` and `panel-reports.md` were read; cited record findings are report-supported and were not independently remeasured here. No project, implementation, scenario, or prior-study material was consulted.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | FACILITATOR-MODELED Final Verdict | FACILITATOR-MODELED Final Verdict Confidence | FACILITATOR-MODELED Final Synthetic-Confidence |
|--------|-----------------|----------------------------|------------------------------|----------------------------------|--------------------------------------------|----------------------------------------------|
| Threat Hunter | Inconclusive | 82 | 44 | Inconclusive | 84 | 54 |
| Detection Engineer | Inconclusive | 80 | 20 | Inconclusive | 82 | 38 |
| Network Forensics | Real | 64 | 30 | Inconclusive | 76 | 40 |
| Host/EDR Forensics | Synthetic | 82 | 66 | Synthetic | 82 | 66 |

The modeled final synthetic-confidence mean is **49.5/100**: `(54 + 38 + 40 + 66) / 4`. The independent initial mean was **40/100**. These arithmetic summaries are not calibrated probabilities, actual revised panel votes, or proof of origin. The modeled range remains 38–66, preserving a meaningful disagreement about how diagnostic the repeated patterns are.

## Round 1 — Submitted Findings

- **Threat Hunter: Inconclusive; verdict confidence 82; synthetic-confidence 44.** Strong positive observations include all 12 visible Windows Type 10 logons matching substantive successful RDP transports, correctly separated Type 9 local and outbound identities, and coherent SSH/SCP/SMB and inspected-proxy pivots. Reservations are six native inventory `sw_vers` lifetimes compressed into 1.983774–1.994358 seconds and shell-oriented Mac document access. The RuntimeBroker document-actor concern is explicitly weak and remains unresolved.
- **Detection Engineer: Inconclusive; verdict confidence 80; synthetic-confidence 20.** Broad process/session checks, event-specific Windows schemas, stable image/hash relationships and local protocol/connection joins survive inspection. Six HTTP response FUID references do not resolve in the available file exports, but filtering/loss is plausible and no complete-export guarantee is established. No high-impact synthetic indicator is demonstrated by this report's tests.
- **Network Forensics: Real; verdict confidence 64; synthetic-confidence 30.** Transport states, packet/header budgets, file payload direction, DNS-to-proxy timing, distinct proxy legs, control/tunnel accounting and certificate relationships are convincing. The unique reservation is 295 iPhone-UA records among 387 requests from Mac-associated `10.10.1.41`; emulation, overrides or forwarding remain plausible. Browser version cohorts carry little independent weight.
- **Host/EDR Forensics: Synthetic; verdict confidence 82; synthetic-confidence 66.** The principal finding is repeated PowerShell-to-SSH delays identical to the millisecond for three different destinations. Additional findings are an approximately 96-second multi-editor launch cadence and cross-host inode differences equal to 482684 for 21 of 24 shared paths, with the remaining three differing by 482685. Counterevidence includes 875/876 matching Sysmon/Security process companions, sound visible lifetime boundaries, and detailed Mac fork/exec and setuid semantics. This report explicitly asserts no impossible event.

## Round 2 — Cross-Examination

### Does coherent lifecycle evidence contradict the host analyst's synthetic judgment?

No. The detection and network reports establish bounded structural consistency. The host report identifies unusual distributions within structurally valid activity. Those claims can simultaneously be true. Successful joins and correct source semantics reduce confidence in crude fabrication, but a careful synthetic source could reproduce them. Conversely, a repeatable script could produce exact timing and a managed image could produce related file metadata in authentic telemetry. Neither side establishes provenance.

The host findings are a blind spot in a verdict based mainly on consistency checks: no process need occur after exit for a repeated timing parameter to be detectable. This is the main reason for the modeled upward revisions in the threat, detection and network scores. It is not a claim that the initial analysts agreed to revise.

### How strong are the repeated Windows launch delays?

This is the strongest qualified indicator. WS-MCHEN's native Sysmon export reports three MAIL-EDGE delays of 5.715 seconds, two MAIL-CLIN delays of 4.235 seconds and two LOG-MON delays of 5.097 seconds, with matching parent PIDs and different executions over hours. The reproducible target-specific equality is more informative than repeated administrative visits alone.

The challenge is automation: a launcher with configured delays can repeat timings, and only seven selected pairs are described. No full conditional delay distribution, script content, or measurement of how many unrelated pairs were searched is supplied. Exact observed equality therefore supports a texture concern, not an impossible-timing finding or a quantified likelihood ratio. Do not prescribe noise solely to erase a legitimate deterministic launcher.

### Do the editor cadence and Mac runtimes independently establish templating?

The editor clusters span approximately 95.731–96.261 seconds across different tools and paths. Varying editor lifetimes make a simple explanation of identical blocking durations weaker. A tutorial, benchmark, scheduled command runner or other automation still fits the observations. The six inventory `sw_vers` lifetimes, spanning only approximately 10.6 milliseconds near two seconds, also differ from the variable interactive executions described by the hunter. A common managed wrapper or inventory service remains an explanation requiring examination.

These are distinct observed patterns across hosts, but their causal independence is unknown. They should not be treated as independent statistical trials or multiplied into near-certainty. Both are distribution texture, and their diagnostic strength depends on whether the intended behavior is interactive or scripted.

### Does inode regularity prove an impossible filesystem?

No. The constant offset across many executable paths is conspicuous, and different file birth dates complicate a simple shared-install-date story. Nevertheless, cloning, filesystem history or identifier sanitization can preserve structured relationships without impossible native records. Internally stable file identities are a positive feature. The supplied evidence supports a qualified numeric-metadata concern, not a schema error or proof that native identifiers could never look this way.

### Is the Mac mobile UA a platform contradiction?

No. A User-Agent is application-supplied; it does not establish the operating system of the request's originating executable. The 295/387 concentration is a concrete contextual anomaly deserving investigation, especially alongside Mac endpoint attribution. Browser overrides, emulation or local forwarding remain viable. Different browser versions across host groups are even less diagnostic without application inventories and management policy. The network report correctly keeps these below hard-contradiction strength.

### Are missing companion rows evidence of generation failure?

Not on the supplied collection description. Six unresolved HTTP FUID references and one unmatched Windows process companion are observed gaps; they are not established contract violations. Late SSH connections need not have an in-window completed connection record. Native ES notification scope and sparse Unified Log coverage also do not guarantee every possible artifact. The initial reports consistently reject penalties for these absences without a retention, visibility or collection guarantee.

## Evidence Classes

### Proven contradictions

**None established in the submitted reports.** No demonstrated impossible process lifetime, principal mismatch, same-sensor tuple disagreement, protocol timestamp impossibility, directional file-byte overflow, or certificate-identity contradiction is presented. This statement describes the checks performed; it is not an exhaustive certification of every record or exact native SDK schema.

### Qualified texture and contextual findings

1. Destination-specific millisecond-exact PowerShell→SSH delays: strongest, with automation as the material alternative.
2. Approximately 96-second mixed-editor cadence: moderate, qualified by tutorials or command automation.
3. Inventory `sw_vers` runtime concentration: moderate, qualified by common service/wrapper behavior and six observations.
4. Cross-host executable inode offsets: moderate, qualified by imaging, filesystem history and sanitization.
5. Mobile-UA concentration on a Mac-associated address: weak to moderate contextual concern; application attribution is unresolved.
6. Mac shell document workflows, browser cohorts and three RuntimeBroker document actors: limited supporting texture; none demonstrates impossible ownership.

### Unsupported collection expectations

Do not infer an error from absent GUI telemetry, missing optional source families, missing pre-window creation or post-window closure, missing per-connection fresh DNS lookups, absent passive TLS 1.3 certificates, six unresolved HTTP FUID references, or a policy message without successful-execution evidence. Additional facts could change these judgments; the supplied reports do not supply those facts.

## Round 3 — FACILITATOR-MODELED Revised Positions

- **Threat Hunter: Inconclusive, confidence 84, synthetic-confidence 54 (up 10).** The native destination-specific delay replays and editor cadence add stronger timing concerns than the hunter's original Mac-only observations. The credible hunting chains remain valid and no attack-lifecycle contradiction emerges. The modeled revision moves toward suspicion while preserving uncertainty.
- **Detection Engineer: Inconclusive, confidence 82, synthetic-confidence 38 (up 18).** The host timing findings expose a distribution dimension that passing schema, identity and interval checks do not answer. The modeled score rises because the evidence base broadens, while bounded correctness checks and viable automation explanations keep it below a synthetic verdict. Missing references retain no independent penalty.
- **Network Forensics: Inconclusive, confidence 76, synthetic-confidence 40 (up 10).** Network-specific positive evidence remains intact. The modeled verdict changes because strong network construction alone cannot resolve endpoint regularity reported by another specialist. The mobile-UA concern gains context, but is not upgraded to proof of a platform mismatch.
- **Host/EDR Forensics: Synthetic, confidence 82, synthetic-confidence 66 (unchanged).** Other reports corroborate the analyst's already acknowledged lifecycle and correlation strengths. They do not directly explain the three principal patterns. The modeled stance stays unchanged because the analyst had already considered automation, imaging and sanitization; reducing or increasing it merely to converge would be artificial.

## Key Agreements

These are agreements evident across the submitted reports, not a new consensus vote.

- The inspected data preserves substantial source-specific semantics and usable cross-source identities.
- Visible process lifetimes, remote-session relationships and protocol budgets have no established hard contradiction in the reported checks.
- Passing those checks supports coherent evidence construction; it does not prove real-world provenance.
- Repeated timing and metadata patterns deserve a separate authenticity assessment from schema correctness.
- Missingness, a compact incident narrative, suspicious-command visibility and optional source scope are insufficient standalone synthetic indicators.

## Key Disagreements

The reports differ chiefly in how much provenance weight to assign to coherent telemetry versus repeated distributions. The host analyst gives the latter enough aggregate weight for Synthetic; the detection analyst's submitted score reflects mainly broad consistency and no high-impact defects. The network analyst's Real lean is explicitly modest. The hunter occupies the middle, recognizing limited texture while finding sound investigative chains. No direct factual conflict between their reported invariants is established. The unresolved issue is attribution of regularity to generation, automation, imaging or transformations.

## Most Convincing Evidence

Ranked by usefulness for this authenticity question, with direction and limits preserved:

1. **Toward synthetic: target-specific exact native launch-delay repetition.** Seven cited pairs at three distinct delays are a concrete, repeatable fingerprint; no impossibility is claimed.
2. **Toward synthetic: mixed-editor launch cadence.** Two reported clusters on a narrow approximately 96-second rhythm support sampled or automated workflow texture; purpose is unresolved.
3. **Toward synthetic: narrow inventory-executable runtimes.** Six approximately two-second native lifetimes contrast with more variable interactive executions; wrappers/services remain plausible.
4. **Toward synthetic: executable-inode offset structure.** Twenty-one equal offsets and three near-equal offsets across two hosts are conspicuous but compatible with transformations or filesystem ancestry.
5. **Toward credible construction: independent source-semantic and lifecycle checks.** Examples include 875/876 native Windows process companions, substantive successful transports for all 12 Type 10 logons, and separately balanced proxy control/tunnel legs. This is strong evidence of technical coherence and weak evidence of origin by itself.

The first four are related texture observations of unknown causal independence; their ranking does not turn them into proven contradictions.

## Most Debated Points

- Whether exact destination-conditioned delay repeats represent a reusable generator parameter or an actual scripted launcher.
- Whether mixed editors and tight inventory runtimes describe intended human behavior or deliberate automation.
- Whether correlated inode identifiers were native, imaged, or sanitized.
- How much passing native-schema/correlation checks can move an authenticity verdict when synthesis can preserve those properties.
- Whether the mobile UA is a contextual mismatch or an application-level override.

## Improvement Recommendations — FACILITATOR-MODELED Common Ground

These recommendations combine submitted suggestions and preserve their stated alternatives; no newly reconvened consensus is claimed.

1. **Investigate the exact launch-delay groups before changing timing.** Measure all matching PowerShell→SSH pairs by destination and initiating process, establish whether a script intentionally controls the delay, and retain that determinism if it reflects the activity. If the records are intended to depict interactive invocation, use task-appropriate per-invocation timing while preserving parent identity and transport-before-auth ordering.
2. **Make development timing reflect the intended workflow.** Validate why unrelated editors and repositories are entered on a repeated approximately 96-second cadence. For intended interactive work, connect spacing to task duration and project transitions and retain persistent user/editor preferences. Preserve explicit benchmark/tutorial automation when that is the explanation.
3. **Validate inventory process duration against the actual command or wrapper.** The six native `sw_vers` lifetimes are the concrete target. Represent the executable's own measured lifetime and any wrapper waits at the correct process boundary; preserve fork/exec/exit semantics rather than applying arbitrary jitter.
4. **Keep filesystem identity and installation history coherent.** Determine whether the two hosts' inode relationships arise from imaging or sanitization. If generating native-style identities, avoid an unexplained path-rank-plus-host-offset pattern across unrelated executables. If identifiers were transformed, document that transformation with collection context.
5. **Resolve application ownership where the reports identify contextual anomalies.** Check `10.10.1.41`'s 295 mobile-UA records against the invoking application or forwarding path; retain mobile emulation when supported. Check the 11 Mac mounted-share shell operations and three RuntimeBroker document actors against their actual intended workflows before changing their ownership or operation mix.
6. **Clarify export retention instead of inventing companions.** Inspect the six specific HTTP FUID gaps and isolated process companion gap. Supply rows only if the export contract requires them; otherwise record the filtering/loss assumption. Preserve existing source-specific schemas, lifetimes, credential distinctions and proxy/SSH/RDP/SMB relationships.

**Modeled outcome:** Inconclusive overall, with material and actionable distribution-texture concerns, no established hard contradiction, and persistent disagreement about whether automation or synthesis best explains the regularities.
