# Deliberation Summary

## Panel Composition

| Expert | Initial verdict / confidence / synthetic-confidence | Final verdict / confidence / synthetic-confidence |
|---|---|---|
| Threat Hunter | Inconclusive / 62 / 52 | Inconclusive / 66 / 51 |
| Detection Engineer | Inconclusive / 78 / 47 | Inconclusive / 76 / 51 |
| Network Forensics Analyst | Synthetic / 68 / 66 | Inconclusive / 62 / 58 |
| Host/EDR Forensics Analyst | Synthetic / 55 / 34 | Inconclusive / 60 / 42 |

Initial values are copied from the reports. Final values are facilitator estimates after comparing those reports; they are not re-interviewed measurements or new dataset measurements. “Synthetic-confidence” is retained as each report’s 0–100 synthetic-likelihood score and is distinct from verdict confidence.

**Round 1 — Initial positions.** The Threat Hunter and Detection Engineer were inconclusive, citing strong cross-source or source-format consistency alongside unresolved texture concerns. The Network Analyst judged the sample synthetic, primarily because of the coincident 14:30–14:45 UTC traffic surge. The Host/EDR Analyst gave a low-confidence synthetic lean (34 synthetic-confidence), while emphasizing that no hard contradiction was found and that exact correlation alone is not a defect.

**Round 2 — Cross-examination.** The surge is a concrete distribution anomaly across two sensors, but its mixed traffic and protocol variety leave a workload burst as an alternative explanation; no report demonstrates impossibility. The Mac flow concentration and repeated Jira activity are independently concerning texture observations, yet could reflect a shared internal application and active user work. Conversely, strong host/network joins and complete-looking sequences establish internal coherence, not provenance. The DC-01 WMI/SYSTEM attribution gap deserves investigation but does not show that the records are fabricated. Sparse Unified Log coverage and events outside the sampled window were correctly not treated as defects.

**Round 3 — Facilitated revisions.** Both initially inconclusive reviewers remain inconclusive, with only small score adjustments because the other reports add texture concerns but no hard contradictions. The Network Analyst moves to inconclusive: the surge remains the strongest synthetic signal, but the reports supply plausible alternatives and substantial protocol coherence. The Host/EDR Analyst also moves to inconclusive: other reviewers provide concrete distribution concerns beyond its own weak alignment signal, while its own evidence still contains no contradiction. These revisions reflect evidence weighting and rubric discipline, not new measurements.

**Round 4 — Disagreement retained.** The panel does not reach a synthetic or authentic consensus. Two reviewers began inconclusive and two began synthetic; after deliberation all four positions are inconclusive, but confidence and synthetic-confidence remain meaningfully different. The Network Analyst’s concern about the coordinated surge remains stronger than the other reviewers’ concerns.

## Key Agreements

- No report identifies a confirmed hard contradiction, impossible process ordering, or malformed source record.
- Cross-source coherence is substantial: the support upload, database export, PsExec effects, process lifecycles, and Zeek UID relationships are corroborated across relevant records. Correlation is evidence of internal consistency, not proof of authentic provenance.
- The coordinated network surge and repeated Mac-to-10.10.3.20:8080 traffic are the clearest distribution-texture concerns. Neither is conclusive without operational context.
- The DC-01 SYSTEM activity has an attribution gap. It supports follow-up investigation, not a synthetic verdict by itself.
- The reports appropriately avoid treating narrative design, missing out-of-window events, or sparse coverage as synthetic evidence without a concrete defect.

## Key Disagreements

- The Network Analyst gives the synchronized 14:30–14:45 UTC core/DMZ surge enough weight for an initial synthetic verdict. The other reviewers treat distribution patterns as cautionary signals that do not overcome coherent records and plausible alternatives.
- Reviewers differ on the force of coordinated activity: repeated Mac flows and recurring command sequences may be patterned generation, or may reflect the same user and a shared internal service.
- The Host/EDR Analyst’s initial synthetic verdict carried only a 34 synthetic-confidence score and was explicitly a cautious lean; it was less decisive than the Network Analyst’s 66.
- No reviewer establishes whether the suspicious DC-01 changes, Westbridge download, or database export were authorized. Maliciousness/authorization and synthetic provenance remain separate questions.

## Most Convincing Evidence

1. **Coordinated network surge (synthetic-texture concern).** The Network Analyst reports 2,093 \`zeek-core\` and 2,029 \`zeek-dmz\` connections during 14:30–14:45 UTC, versus lower counts in adjacent intervals; 1,528 core connections were initiated by 10.10.3.10. The simultaneous rise is conspicuous, though it contains mixed activity and is not shown to be impossible.
2. **Mac flow concentration (synthetic-texture concern).** The Detection Engineer reports 288/371 and 372/465 eCAR FLOW records on two Macs targeting 10.10.3.20:8080, with a short repeated Chrome/Jira cluster. The scale and repetition merit context; a shared application remains a plausible explanation.
3. **Support archive correlation (internal-coherence evidence).** The Threat Hunter reports Lina’s shell history, endpoint records, and Zeek HTTP/file evidence agreeing on the archive, destination, successful upload, and 1,572,864-byte size.
4. **Database export and staging correlation (internal-coherence evidence).** The Threat Hunter reports matching root \`mysqldump\`, gzip, SCP, endpoint receipt, and Zeek SMB write evidence for the 191,097-byte staged archive.
5. **Different DC-01 episodes should not be conflated.** The Host/EDR report describes an explicitly sourced PsExec sequence with successful type 3 logon and corroborated service/process effects. The Threat Hunter describes a separate later WMI/SYSTEM sequence whose initiating identity is unclear. The first supports operational coherence; it does not resolve attribution for the second.

## Most Debated Points

- **Whether the surge is synthetic or operational:** Two sensors rise together sharply, but the interval includes varied proxy, service, and scan-like activity. No report compares it with an independent workload baseline or establishes a generation-specific pattern.
- **Whether repeated Mac traffic is an artifact:** Similar destination concentration and command sequences occur on both hosts, but both belong to Maya Ross and could reflect routine use of one internal application.
- **How much coherent evidence should affect provenance:** Cross-source agreement strongly supports that the records fit together. It cannot independently establish that the underlying activity was collected from a real environment.
- **Whether attribution gaps are quality defects:** The missing initiating identity for DC-01 WMI activity is important for investigation, but the reports do not establish that the event sequence violates source semantics.

## Improvement Recommendations (Consensus)

No dataset or generation change is supported by a specific recommendation shared by most or all reviewers. The panel’s reports support retaining the cross-source relationships and avoiding changes based only on matching records, sparse coverage, or out-of-window absence. The anomaly-specific suggestions—checking the 14:30–14:45 workload context, reviewing the Mac application cadence, and resolving DC-01 WMI attribution—remain targeted follow-up items rather than consensus dataset fixes.
