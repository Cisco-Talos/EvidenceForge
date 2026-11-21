# Deliberation Summary

This synthesis records the four original reports and four actual individual deliberation responses. The facilitator supplies no fifth assessment, revised vote, or score. The responses document cross-examination and individual rechecks; they are not a transcript of a live discussion. All measurements below are attributed to those submissions rather than new facilitator inspection of the underlying logs.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 84 | 67 | Synthetic | 87 | 70 |
| Detection Engineer | Real | 62 | 28 | Synthetic | 80 | 66 |
| Network Forensics | Inconclusive | 82 | 44 | Synthetic | 76 | 63 |
| Host/EDR Forensics | Inconclusive | 82 | 43 | Synthetic | 84 | 66 |

Verdict confidence and synthetic-confidence are distinct quantities. In particular, Network Forensics became less confident in its chosen verdict (82 to 76) while assigning greater synthetic-confidence (44 to 63). Its earlier confidence concerned an Inconclusive assessment, not confidence that the collection was real. No score was inferred or changed by the facilitator.

## Round 1 — Present Findings

- **Threat Hunter — initially Synthetic, confidence 84, synthetic-confidence 67.** Its principal finding was a common Linux PID-increment floor: ten hosts each had 36 sysstat shell jobs; 67 of 350 successive within-host PID differences were exactly +940, and +940 was every host's minimum. Native CRON records corroborated representative IDs. Its weaker concern was seven cat-attributed reads of binary office documents on one Mac. Its hunting-specific counterevidence included coherent SSH pivots, database dump/compression/transfer ordering, and distinct observations of the same transfer at different sensors. It expressly did not penalize an easy-to-follow suspicious narrative.
- **Detection Engineer — initially Real, confidence 62, synthetic-confidence 28.** Event-specific Windows XML fields, visible process/session relationships, normalized actor lifetimes, and native macOS fork/exec distinctions were credible. Apparent Zeek payload/header accounting deficits were explainable by recorded capture loss. Concentrated irqbalance and snapd strings were only weak concerns because fixed diagnostics and common fleet images are plausible. Its unique contribution was detailed schema and accounting restraint, including rejection of 176 apparent direction-level shortfalls as impossible-byte findings.
- **Network Forensics — initially Inconclusive, confidence 82, synthetic-confidence 44.** Protocol state/history and packet bounds, passive TLS visibility, TLS 1.2 chain/key relationships, proxy control-versus-tunnel byte scope, and sensor-local differences held up under its checks. The strongest concern was 34 routine TXT transactions across 21 clients, exclusively 17:41:44.208597–18:03:34.090233 UTC within a roughly six-hour slice. A coordinated diagnostic or application action could explain that cohort. No impossible network relationship was demonstrated.
- **Host/EDR Forensics — initially Inconclusive, confidence 82, synthetic-confidence 43.** Fresh shell-to-SSH launches reproduced actor/destination-specific non-round delays: three Marcus-to-APP-INT-01 pairs were 3.921258, 3.920926, and 3.921114 seconds apart from their parents. Other destinations/users supported the same timing concern. Security timestamps following all 955 paired Sysmon process creations by about 35–643 ms were much weaker evidence because provider/export conventions were unresolved. Stable identities, valid visible lifecycles, netonly credential distinctions, and differentiated Linux/macOS workflows provided substantial counterevidence.

## Round 2 — Cross-Examination

### Identity consistency versus identity-distribution texture

The initial split was principally a difference in tested properties and evidential weight, not conflicting measurements. Valid native identities and lifecycles do not rule out an unrealistic distribution of allocated identities. The Detection Engineer, Network Forensics analyst, and Host/EDR analyst each explicitly report independently reproducing the Threat Hunter's PID finding during deliberation. All report 350 adjacent differences, 67 exact +940 values (19.14%), ten identical minima, and 261 distinct differences overall, with values up to 5,545. This is a repeated lower bound beneath variable allocations, not a constant copied sequence.

Native corroboration makes a normalized-only display artifact inadequate; the Host/EDR analyst reports matching native CRON PID sequences on all ten affected hosts, while the other submissions describe representative native checks. The analysts agree that centrally managed cron explains the shared command and ten-minute schedule. A standardized hidden process/thread workload remains conceivable, and the Threat Hunter also retains systematic identity remapping during sanitization as an alternative. The panel considers the shared exact floor across diverse roles more persuasive than those unestablished explanations. Nobody calls it a kernel impossibility, a generator identity leak, or a hard contradiction.

### Recurrent launch delays versus managed automation

The Threat Hunter, Detection Engineer, and Network Forensics analyst report rechecking the Host/EDR analyst's principal Sysmon examples. The three approximately 3.921-second delays span separate parent/child pairs over about 1 hour 46 minutes and differ by only 0.332 ms. This is more specific than ordinary repeated administration. It remains compatible with a saved launcher, fixed workflow, shell startup behavior, automation, or timestamp reconstruction; manual typing was never established. The submissions treat the destination examples as one supporting timing issue rather than multiple independent defects.

### Late TXT cohort versus a coordinated job

The Threat Hunter and Detection Engineer report reproducing Network Forensics' 34-query/21-client cohort after separating the visibly suspicious query-name populations. Host/EDR explicitly did not rerun this network calculation during deliberation and treats it as supporting context, not the determinant of its revised verdict. Fleet diagnostics, security tooling, scheduled mail-policy checks, or coordinated application behavior remain credible explanations. A six-hour slice cannot establish long-term normal DNS cadence, and no missing process/source requirement follows from the cohort.

### Timing and apparent gaps: challenges that limited the case

- Native macOS sshd-session execution precedes Unified Log acceptance in the examined sessions. Delayed normalized transitions do not establish execution-after-authentication or process-before-existence contradictions.
- Linux eCAR/syslog offsets remain ambiguous without occurrence-versus-collection timestamp semantics. The analysts do not score those offsets as hard contradictions.
- Universal Security-after-Sysmon ordering could reflect provider/export behavior. The bounded positive offset stays weak and is not elevated to a source-native impossibility.
- The 176 apparent network accounting shortfalls remain covered by recorded missed bytes. The unmatched SMB mapping remains compatible with collection-window connection logging. Neither contributes synthetic weight.

## Round 3 — Actual Revised Positions

| Expert | Submitted revision and reason |
|--------|-------------------------------|
| Threat Hunter | Remains **Synthetic**; verdict confidence **84 → 87**, synthetic-confidence **67 → 70**. Its independently verified SSH timing supplies modest additional support to the existing PID finding. It removes binary-document cat behavior from active score contribution. |
| Detection Engineer | Changes **Real → Synthetic**; verdict confidence **62 → 80**, synthetic-confidence **28 → 66**. Newly verified PID texture is primary; repeated SSH timing and the TXT cohort support it. Its successful schema/lifecycle checks remain valid and do not become synthetic indicators. |
| Network Forensics | Changes **Inconclusive → Synthetic**; verdict confidence **82 → 76**, synthetic-confidence **44 → 63**. Rechecked PID texture is primary and SSH timing supporting; network findings remain substantially production-like. Credible operational alternatives and absence of a hard contradiction keep its score comparatively restrained. |
| Host/EDR Forensics | Changes **Inconclusive → Synthetic**; verdict confidence **82 → 84**, synthetic-confidence **43 → 66**. Its rechecked cross-host PID distribution is stronger than its original timing concern and drives the change. Recurrent startup timing is secondary; the un-rechecked DNS cohort is context only. |

## Key Agreements

All four final submissions judge the collection likely synthetic, with final synthetic-confidence scores from 63 to 70. Their common basis is distribution texture, chiefly the shared Linux PID floor, rather than a newly discovered impossible event or malformed native schema.

All preserve substantial positive evidence: coherent tested process/session relationships, platform-specific native semantics, useful hunting pivots, and credible network behavior. Accurate relationships and suspicious statistical texture can coexist. Complete correlation alone proves neither real nor synthetic provenance.

The analysts retain plausible operational explanations and do not assign scores in the 81–100 range. Their convergence is an informed likely-origin judgment, not proof of fabrication.

## Key Disagreements

The initial Real/Synthetic/Inconclusive split resolves at the verdict level after shared evidence and individual rechecks. It does not resolve every uncertainty or equalize scores. Network Forensics remains most restrained (63), emphasizing strong network realism and operational alternatives; the Threat Hunter remains most persuaded (70), with the same central PID concern it identified initially. The two other reviewers finish at 66.

Weight also differs: the TXT cohort is reproduced and moderately weighted by Detection Engineering, contributes little beyond stronger findings for the Threat Hunter, and is non-determinative context for Host/EDR. Automation, shared background workloads, exporter conventions, and coordinated diagnostics are not disproved. There is no submitted final dissenting verdict, and no basis to invent a further round of score alignment.

## Most Convincing Evidence

The ordering below synthesizes the reviewers' stated weights; it is not a separate panel ranking vote.

1. **Shared Linux PID floor — strongest synthetic indicator.** Ten hosts, 350 adjacent sysstat-job pairs, 67 exact +940 differences, and +940 as every host's minimum, corroborated natively. All four final positions make this primary. Classification: distribution_texture; hidden shared workloads or systematic remapping remain alternatives.
2. **Repeated fresh shell-to-SSH delays — supporting synthetic indicator.** Independently rechecked millisecond-level recurrence across separate sessions; additional destinations corroborate the same concern. Classification: distribution_texture; automation/workflow alternatives remain.
3. **Late broad routine-TXT cohort — secondary synthetic indicator.** Thirty-four transactions across 21 clients confined to approximately 22 minutes. Reproduced by the Threat Hunter and Detection Engineer; not independently rerun by Host/EDR. Classification: distribution_texture; coordinated diagnostics remain plausible.
4. **Source-native and lifecycle coherence — strongest counterweight.** No demonstrated hard contradiction emerged in tested identities, native Mac SSH transitions, packet/capture-loss accounting, passive TLS visibility, or proxy byte scopes. These observations support realism and usability without independently authenticating provenance.

## Most Debated Points

The central question is whether shared numerical texture outweighs strong source-native coherence. The actual revisions answer yes, within the likely-synthetic band. Another recurring question is whether apparent timing inversions survive comparison of native occurrence evidence with normalized observation time; examined Mac examples do not, and Linux timestamp semantics remain unresolved. Finally, managed automation and coordinated diagnostic behavior are plausible explanations for repeated timing and DNS cohorts, so neither finding warrants arbitrary noise or an impossible-lifecycle claim.

### Withdrawn, corrected, and non-contributing evidence

- The Threat Hunter explicitly withdraws binary-document cat reads from active score contribution. The other final responses give them little or no material weight; executable but unusual CLI behavior is not a required missing-GUI-source defect.
- Host/EDR corrects its original description of the MeetingAssist policy observation as a “rejected attempt.” The message says policy “would not allow” execution; that alone proves neither enforcement nor denial. It contributes no synthetic weight, and no demonstrated contradictory successful child chain was found.
- The apparent Chrome descriptor concern disappears on inspecting the recorded FD 3 pipe. Builtin service LUID reuse is not an ordinary-session chronology defect.
- Repeated irqbalance/snapd vocabulary remains weak: fixed diagnostics, common hardware, installed software, and fleet images are credible. It is not counted as another strong independent defect.
- No weight is assigned to domain sanitization itself, easy-to-follow suspicious narratives, absent selected Sysmon families, sparse Unified Log selection, completeness of source matching, or initiators/terminators outside the slice.

## Improvement Recommendations (Consensus)

1. **Model host-specific process allocation and background churn.** All four final submissions prioritize removing or operationally explaining the universal +940 floor. Recheck successive sysstat-job PID deltas across roles and hosts while retaining normal cron cadence and native/normalized identity agreement.
2. **Make launch timing follow the actual intended workflow.** All four support independent startup variation where launches are independent. Preserve fixed-delay timing when a real automated launcher explains it, with that operational explanation represented; do not add arbitrary jitter to intentional automation.
3. **Tie routine TXT activity to its producing application, role, or coordinated job.** All four support examining the late 34-query cohort. Distribute genuinely independent routine checks according to their real schedules, or retain evidence/context for the coordinated diagnostic action. Do not manufacture required collectors.
4. **Preserve the realism already demonstrated.** Retain native event schemas, durable identities, process/session lifetimes, platform-specific exec semantics, source-specific timestamps, passive TLS limits, proxy byte scopes, and sensor capture-loss differences when improving statistical texture.

Host/EDR additionally recommends explicit occurrence/collection timestamps or documented clock-normalization conventions for ambiguous eCAR timing. Other responses support the timing qualification, but no formal all-panel vote adopted this as a separate product requirement. Initial irqbalance/snapd vocabulary recommendations remain lower-priority specialist suggestions rather than the final consensus's main driver.

## Methodological Limitations

The reviewed collection is approximately six hours on 2026-11-02 with selective source coverage. It cannot establish full-day behavior, exhaustive process/thread churn, packet provenance, or all exporter timing semantics. Tests were bounded to supplied visible identities and fields, not exhaustive provider-manifest certification, executable-byte hash authentication, or proof of every possible correlation.

The deliberation responses report individual rechecks after the experts read shared reports; their convergence is therefore informed by shared evidence rather than four independent discoveries of the same indicators. Findings from multiple destinations or sources are not automatically independent defects, and scores are neither calibrated probabilities nor a basis for a new facilitator score. This synthesis adds no outside data, scenario/ground-truth knowledge, or new log inspection. The final unanimous verdict remains qualified by credible operational explanations and the absence of a demonstrated hard contradiction.
