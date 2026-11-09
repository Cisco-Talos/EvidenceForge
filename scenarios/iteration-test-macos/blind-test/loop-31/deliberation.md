# Deliberation Summary

This is a facilitator synthesis of four submitted independent reports, not a fifth independent review. Only the four reports and the deliberation instructions were consulted. No underlying records, repository content, scenarios, or previous assessments were inspected. All revised verdicts, confidences, and scores below are **facilitator-modeled positions**, not actual reconvened expert votes. Agreements and disagreements describe the submitted evidence or the modeled discussion; no expert has endorsed this synthesis.

## Round 1 — Present Findings

### Threat Hunter

- Initial verdict: **Synthetic**; verdict confidence **86/100**; synthetic-confidence **66/100**.
- Strongest evidence: two Mac histories repeat the same 30/37/44/51/65-second gaps across changing diagnostic commands; ordinary shared-document operations uniformly use `cat`/`tee`; initial Chrome helper launches have nearly identical +2/+3/+5-second schedules.
- Distinct contribution: the cross-host arithmetic progression in history provides another view of the Mac timing pattern. The report also demonstrates useful credential-cloning, SSH, and staged-transfer pivots, while explicitly declining to count the neatness of suspicious activity as an authenticity tell.
- Limitation: all scored findings concern distribution texture; no impossible lifecycle or native schema contradiction was established.

### Detection Engineer

- Initial verdict: **Inconclusive**; verdict confidence **85/100**; synthetic-confidence **48/100**.
- Strongest reservation: native Mac fork events retain identical six-digit fractional seconds across separate commands tens of seconds apart. Legitimate scripted scheduling remains a plausible explanation.
- Distinct contribution: comprehensive parse/reference/lifecycle checks and source-specific Windows event examples support practical detection usability. Three normalized Mac transition pairs serialize dependent updates before their establishing exec at equal milliseconds; this is replay ambiguity rather than proven inverted event time.
- Limitation: passed physical byte bounds and UID joins do not test the particular Zeek history/payload relationship identified by the network specialist.

### Network Forensics

- Initial verdict: **Synthetic**; verdict confidence **84/100**; synthetic-confidence **64/100**.
- Strongest evidence: TCP/514 records have lowercase `d` in history, reported as responder data, with `resp_bytes=0`. The report counts 44 core and nine database sensor observations and identifies normal-close, reset, and half-closed variants. These counts overlap across sensors and represent one defect family.
- Distinct contribution: this is the only reported hard field-semantic contradiction. The reset example has both payload counters zero and history `ShAdr`, while broad DNS, TLS, certificate, file-flow, and connection-timing checks otherwise pass.
- Limitation: an exporter/transformation defect can produce contradictory real-origin logs; a hard contradiction in the exported artifact is not proof of synthetic provenance.

### Host/EDR Forensics

- Initial verdict: **Synthetic**; verdict confidence **84/100**; synthetic-confidence **65/100**.
- Strongest evidence: 35/55 zsh fork records form 15 exact-fraction groups across two Macs, including local and SSH shells. Native exec arguments corroborate repeated `cat`/`tee` use for PDF and Office documents.
- Distinct contribution: the timing recurrence spans multiple shell contexts, while separate exec timestamps vary. The report also validates differentiated Mac launch chains, Windows PID/hash coherence, and layered Linux SSH evidence.
- Limitation: no impossible lifetime or native schema error was established. Missing native process exits coincide with sequence gaps and were correctly left unscored.

## Round 2 — Cross-Examination

### Apparent contradiction: clean network checks versus inconsistent TCP history

The detection and threat reports describe sound byte bounds and references; the network report identifies a narrower semantic failure. These findings are compatible. Payload not exceeding IP bytes, nonzero bytes having packets, and valid protocol UIDs do not imply that every history symbol agrees with directional payload. The stronger evidence for this particular question is the network report's named rows, counters, history strings, close states, and repeated scope.

Challenge: could the lowercase `d` mean an acknowledgment, or could packet loss explain zero payload? The network report explicitly distinguishes responder data from acknowledgments and supplies `missed_bytes=0` examples, including the reset case. Within the supplied reports there is no competing semantic interpretation or row-level rebuttal. The facilitator can therefore carry this forward as a **reported hard contradiction in exported fields**, conditional on the report's interpretation and measurements; this facilitation did not independently verify them. It remains localized to TCP syslog and is not evidence that all network activity is defective.

Challenge: could real telemetry contain this? Yes. The network expert explicitly permits an exporter or transformation bug. That alternative limits provenance confidence even if the artifact contradiction is accepted. The remedy should preserve genuine one-way traffic, not fabricate response payload.

### Main disagreement: how much provenance weight should Mac scheduling carry?

Threat, detection, and host specialists substantially agree on the observation but differ on its significance. Threat emphasizes matching arithmetic gaps across hosts; host emphasizes exact fractional phases across local and SSH shells; detection retains an automation explanation and consequently stays inconclusive.

Challenge: are three reviewers three independent confirmations of synthetic origin? No. Much of their evidence comes from the same underlying Mac activity. History and native ES corroborate the timing observation; they do not create independent defect families. The detection totals cover all native forks, whereas the host's 35/55 denominator is limited to zsh forks. Those are different populations, not inconsistent measurements.

Challenge: could a diagnostic script preserve integer spacing and a repeated scheduling phase? Yes; all three reports allow automation, and the submitted reports do not establish the absence of a script. Exact phase retention across irregularly spaced commands, coupled with cross-host arithmetic progression, strengthens the texture concern beyond simple routine repetition, but it does not turn it into an impossible lifecycle. A reconstructed exporter timeline is another surviving alternative. Browser helper startup is particularly compatible with deterministic application behavior and deserves little additional weight.

Modeled resolution: retain a moderate timing indicator and keep its scope explicit. The network defect adds a separate reason for suspicion; it should not retroactively make the Mac timing a hard contradiction.

### Document handling: behavioral narrowness versus legitimate CLI operations

Threat and host describe binary Office/PDF reads through `cat` and writes through `tee`; native exec arguments corroborate the process mapping. This is more concrete than a normalized-label misunderstanding. Nevertheless, these commands can read or write arbitrary bytes. Troubleshooting, scripted testing, or selected collection can explain a small sample. Eight visible reads and two writes are not a representative survey of all business document usage.

Modeled resolution: supporting distribution evidence only, weaker than the timing pattern. Visible GUI applications make the mapping worth investigating, but do not prove that any particular file operation had to belong to a GUI process. Two experts citing the same operations must not double its weight.

### Same-millisecond Mac transitions: replay concern versus impossible chronology

The detection report explicitly supplies equal `timestamp_ms` values and correctly ordered native exec evidence. Millisecond truncation can collapse distinct native transitions. A dependency-aware consumer can recover order, while a naive stream replay can misapply credentials or execution versions.

Modeled resolution: retain a concrete downstream usability recommendation, with negligible independent authenticity weight. Do not promote this to a process-lifetime contradiction or combine it with missing exits; the host report gives sequence-gap context for those omissions.

### What the positive evidence establishes

The reports agree that process identities, visible session lifetimes, source tuples, protocol references, certificate identities, and detailed credential/transfer relationships are often strong. These observations weaken claims of pervasive elementary breakage and explain the moderate scores. They support hunt feasibility and internal consistency; they do not by themselves identify real provenance. Conversely, readable attack narratives, sanitized names, selected source coverage, and the six-hour window remain neutral.

## Round 3 — Revised Positions

The following are **facilitator-modeled positions only**, not actual expert revisions or votes. Numeric changes are reasoned synthesis, not calibrated probabilities or newly measured evidence.

- **Threat Hunter: Synthetic, verdict confidence 88, synthetic-confidence 69** (from 86 and 66). The separate reported TCP history contradiction modestly strengthens a conclusion previously based on Mac texture. The exporter/script alternatives and strong hunt coherence keep the change small.
- **Detection Engineer: Synthetic, verdict confidence 78, synthetic-confidence 61** (from Inconclusive, 85 and 48). Acceptance of the narrow history/payload finding supplies a semantic defect outside the initial checks. The modeled verdict changes, but confidence in that new verdict is lower than the original confidence in being inconclusive because real-export corruption remains plausible. Mac timing alone would not justify this revision.
- **Network Forensics: Synthetic, verdict confidence 86, synthetic-confidence 68** (from 84 and 64). The Mac timing evidence adds a different source-family concern without enlarging the network defect's scope. Three reports discussing the same Mac behavior are counted as corroboration, not three new independent signals.
- **Host/EDR Forensics: Synthetic, verdict confidence 87, synthetic-confidence 69** (from 84 and 65). A separate source-native network consistency issue modestly strengthens the existing endpoint-texture judgment. Endpoint hard contradictions are still not claimed.

## Round 4 — Consensus Summary

### Panel Composition

Final columns contain **facilitator-modeled positions, not reconvened expert votes**.

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Modeled Final Verdict | Modeled Final Verdict Confidence | Modeled Final Synthetic-Confidence |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Synthetic | 86 | 66 | Synthetic | 88 | 69 |
| Detection Engineer | Inconclusive | 85 | 48 | Synthetic | 78 | 61 |
| Network Forensics | Synthetic | 84 | 64 | Synthetic | 86 | 68 |
| Host/EDR Forensics | Synthetic | 84 | 65 | Synthetic | 87 | 69 |

Initial score mean: **60.75/100**. Facilitator-modeled final score mean: **66.75/100** = (69 + 61 + 68 + 69) / 4. This is a modest likely-synthetic synthesis with substantial uncertainty, not an empirical consensus probability.

### Key Agreements

- The collection has substantial internal and cross-source coherence and supports meaningful hunting. The reported findings do not justify a broad broken-lifecycle claim.
- Three reviewers observe related Mac timing regularity. They differ mainly in interpretation, not in the basic occurrence of repeated phases and gaps.
- Missing optional sources, filtered exports, outside-window lifecycle endpoints, sanitized names, and narrative completeness are not scored defects.
- The TCP history/payload issue is one localized reported semantic contradiction; Mac timing and document handling are distribution evidence; equal-millisecond ordering is a replay concern.

### Key Disagreements

- The detection expert's submitted position remains inconclusive; the other three submitted positions are synthetic. The modeled shift is not evidence that the detection expert actually changed their mind.
- A diagnostic script or timestamp reconstruction remains a plausible explanation for Mac timing; a production exporter defect remains plausible for TCP syslog. No submitted report settles those provenance alternatives.
- Browser helper launch schedules and document CLI mappings carry less weight than their repeated appearance might suggest. Their small scope and legitimate deterministic/scripted explanations prevent high-confidence provenance inference.

### Most Convincing Evidence

1. **Reported hard contradiction:** responder-data history `d` with zero responder payload in repeated TCP/514 observations, including `zeek-core/conn.json:209` and the reset example at `:10352` / `zeek-db/conn.json:339`. Strongest artifact-consistency finding; exporter corruption remains an alternative to synthesis.
2. **Distribution texture:** repeated exact Mac fork fractions across separately timed local/SSH commands, with matching arithmetic gap patterns across hosts. Treat the three reports' overlapping observations as one timing family.
3. **Positive consistency evidence:** strong process/session lifecycles, credential-clone identity separation, SSH transport/auth tuples, and transfer provenance across distinct sources. This supports utility and constrains the scope of negative claims.
4. **Supporting distribution texture:** `cat`/`tee` exclusively mediating the small visible set of ordinary Mac shared-document reads/writes despite desktop applications being present. Possible in real workflows and weaker than timing.

### Most Debated Points

- Whether observed Mac bursts represent unmodeled automation or synthetic scheduling. Identical fractional phases are more specific than ordinary regularity, but no submitted report rules automation out.
- Whether inconsistent network fields identify synthetic origin or defective real-data export. The contradiction and the provenance inference must remain separate.
- How strongly to credit source coherence: it demonstrates useful behavior without proving real origin, and it should prevent inflated dataset-wide defect claims.
- How normalized equal-time ordering affects consumers without establishing an impossible native sequence.

### Improvement Recommendations (Facilitator Synthesis of Shared or Complementary Findings)

These are recommendations derived from the submitted reports, not unanimously approved decisions.

1. **Align TCP history with directional traffic facts.** Construct or preserve history and payload counters from a common representation. For genuine one-way syslog, allow acknowledgments/FINs without responder-data `d`. Exercise SF, RSTR, S2 and zero-payload reset variants at each sensor; avoid treating overlapping sensors as separate behavior and avoid inventing response bytes to make a string pass. For real exports, inspect transformation/history construction first.
2. **Give independently initiated Mac commands distinct timing.** Preserve fork-before-exec and associated history relationships, while allowing separate subsecond phases and task-dependent pauses. If the activity is intentionally scripted, represent its actual invocation/process context so repeated timing has a visible cause. Do not solve this merely by adding random noise to rendered timestamps.
3. **Represent document workflows by their actual actors.** Ordinary spreadsheet, presentation and PDF operations should follow the appropriate application/workflow; retain `cat`/`tee` where diagnostics or scripts truly warrant them. Keep native exec arguments, normalized file attribution, and shared-file identity aligned. The objective is a defensible workflow, not arbitrary process-name diversity.
4. **Make tied normalized transitions replayable.** Preserve dependency order or an explicit transition sequence when millisecond timestamps tie, establishing the relevant exec identity before its service-drop/job-control update. Keep this separate from native timing claims.
5. **Preserve demonstrated strengths while making changes.** Maintain stable process/session identities, differentiated platform launch paths, transport-before-auth ordering, local/outbound principal separation, transfer provenance, UID/certificate references, and explicit native collection gaps. Additional unrelated source families would not address the reported issues.
