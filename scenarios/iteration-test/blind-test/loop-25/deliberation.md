# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 80 | 45 | Synthetic | 87 | 74 |
| Detection Engineer | Inconclusive | 80 | 38 | Synthetic | 84 | 72 |
| Network Forensics | Synthetic | 83 | 68 | Synthetic | 88 | 74 |
| Host/EDR Forensics | Synthetic | 78 | 67 | Synthetic | 88 | 76 |

The final positions above come from the four actual individual deliberation responses. This synthesis structures their reported rechecks and reasoning; it does not represent a live discussion or an additional independent review. The mean revised synthetic-confidence score is **74.0/100**, calculated as **(74 + 72 + 74 + 76) / 4**. It is an arithmetic panel summary, not a separately calibrated probability.

### Round 1 — Present Findings

- **Threat Hunter:** Initially Inconclusive (verdict confidence 80; synthetic-confidence 45). The strongest concern was nine Mac host/path combinations, covering eight executable paths, with access, modification, change and birth timestamps all exactly `2026-10-15T00:00:00.000000000Z`. Strong counterevidence included the workable public-web reverse-shell chain and correctly ordered SSH/SCP transport, authentication, receiver and closure evidence. The distinctive hunting contribution was to establish that the investigated multi-source attack pivots actually worked without treating narrative readability as a provenance defect.
- **Detection Engineer:** Initially Inconclusive (80; 38). Broad Windows XML, eCAR, process-identity and Zeek protocol checks passed. The principal concern was MAC-MROSS-02 PID 1 starting October 6 while its executable birthtime/ctime was October 29, repeated in 11 actor snapshots of that same history. Native macOS fork/exec identity transitions were credible. The reviewer uniquely documented one unmatched SMB mapping UID, explicitly assigning it no independent upward score because export filtering or loss could explain it.
- **Network Forensics:** Initially Synthetic (83; 68). The strongest concern was directional byte conservation across inferred opaque CONNECT legs, despite exact client/proxy control-plus-tunnel arithmetic. The selected diagnostic screen reported 90 mismatches among 479 eligible matches, with 47 having the stronger directional shortfall. Counterevidence included coherent DNS, TLS, certificate and connection relationships and realistic protocol/state diversity. Cross-leg payload accounting was this reviewer's distinctive contribution.
- **Host/EDR Forensics:** Initially Synthetic (78; 67). Ten fork observations across three groups on two Macs preserve exact microsecond phases over variable whole-second gaps; matching monotonic-clock increments reinforce this single timing-texture finding. Windows identity/lifecycle checks and 43 matched Linux SSH transport-before-acceptance checks passed. Distinguishing native fork occurrence times from subsequent exec observations was this reviewer's distinctive contribution.

### Round 3 — Revised Positions

Both initially inconclusive reviewers changed to Synthetic after independently rechecking the fork-phase and proxy-accounting examples. The Threat Hunter moved from 45 to 74 synthetic-confidence and from 80 to 87 verdict confidence. The Detection Engineer moved from 38 to 72 and from 80 to 84. Both explicitly retained their favorable schema, lifecycle and practical-correlation findings; those tests had not covered the two newly considered invariants.

Network Forensics retained Synthetic, increasing synthetic-confidence from 68 to 74 and verdict confidence from 83 to 88 after same-DMZ-sensor rechecks of both proxy legs and confirmation of the host timing pattern. Host/EDR retained Synthetic, increasing from 67 to 76 and from 78 to 88 after checking the network examples and the other reviewers' metadata observations. All four retained material uncertainty and declined to characterize the findings as an unconditional hard contradiction. No reviewer moved to the 81–100 synthetic-confidence band.

## Key Agreements

- **Final provenance assessment:** All four actual individual responses favor Synthetic. Their revised synthetic-confidence scores occupy a narrow 72–76 range. This final agreement follows two changed verdicts; the original panel was split between Inconclusive and Synthetic.
- **Two leading concerns:** All four accept the exact native fork-phase pattern as material `distribution_texture` evidence and the proxy directional shortfalls as a substantial `contract_gap`, with the qualifications below. Valid same-flow budgets and valid process ordering do not rebut either issue.
- **Substantial operational realism remains:** Native field shapes, Windows process/session identities, source-aware Mac fork/exec handling, Linux SSH ordering, and practical cross-source pivots remain convincing within the tested scope. The new findings do not invalidate those positive results.
- **Metadata evidence is weaker:** The shared executable timestamp fixture and launchd process/file chronology are confirmed observations with deployment, preservation, alteration or export-normalization alternatives. Repeated snapshots or affected executable paths must not be counted as independent defect families. The Mac findings could share a transformation cause.
- **The orphan SMB mapping stays diagnostic:** A single missing retained connection is compatible with filtering/export loss and adds no independent upward score. The panel does not treat source completeness, readable malicious activity, optional missing artifacts or copied-file timestamps as provenance evidence.

## Key Disagreements

No final categorical verdict disagreement remains in the actual responses. The residual difference is evidentiary weight: Detection Engineer ends at 72, Threat Hunter and Network Forensics at 74, and Host/EDR at 76. The responses do not establish a sharper dispute behind that spread, so none is inferred here.

The initial split reflected different tests and weighting. The two initially inconclusive reviewers had found localized, explainable file-metadata concerns alongside strong lifecycle/schema results. The two initially Synthetic reviewers had identified native occurrence-time texture or cross-leg byte ownership problems outside those screens. All four now accept the compatibility of those findings.

Several explanations remain unresolved rather than voted away. Incorrect inferred proxy-leg association, unlogged additional upstream activity, unusual counter definitions or undocumented TLS transformation could explain the network observations. Reconstructed/export-transformed timestamps could explain the native-looking fork phases, and altered/preserved file metadata could explain the historical chronology. The panel favors synthesis while retaining those credible transformed-real-data alternatives.

## Most Convincing Evidence

The following order reflects the shared emphasis in the responses and Detection Engineer's explicit ranking, not a separate panel ballot. The first two findings carry the main weight; the file-history observations are secondary and potentially related.

1. **Directional payload shortfalls across apparent opaque proxy legs.** Proxy line 823 (`assets.signalwire.dev`) reports 214 CONNECT-response bytes plus 4,074 server tunnel bytes, exactly matching 4,288 client responder bytes, while the candidate upstream supplies only 2,372 server bytes: a 1,702-byte shortfall. Proxy line 448 (`smtp.office365.com`) has 346 client tunnel bytes but the candidate upstream sends 877 client bytes, exceeding even the entire 705-byte client control-plus-tunnel stream. Line 898 (`assets.pollfish.app`) has a 253-byte server-direction shortfall. All four responses confirm at least the first two examples; Detection, Network and Host/EDR confirm all three. Network additionally confirms matching client-leg totals on the DMZ sensor, reducing cross-sensor ambiguity. The relationships still lack a durable cross-leg identifier, so these remain qualified accounting concerns.
2. **Exact native fork occurrence phases across three groups.** MAC-MROSS-01 ES lines 35/38/41/44 retain `.198588000` across 27-, 35- and 19-second gaps; lines 55/58/61 retain `.487145000` across 38 and 29 seconds. MAC-MROSS-02 lines 86/89/92 retain `.965208000` across 22 and 41 seconds. The last group's monotonic increments are exactly 528,000,000 and 984,000,000 ticks. All four responses confirm the pattern. It concerns distinct forks, with separate subsequent exec offsets, rather than multiple renderings of one event. Wall and monotonic fields corroborate the same occurrences and are not independent proofs; timestamp reconstruction remains a credible alternative.
3. **Four collapsed file timestamp meanings across unrelated software.** Nine host/path combinations on both Macs share one precise midnight for access, modification, change and birth metadata. All four responses confirm this pattern and treat it as a moderate fixture/normalization signal. Image deployment or export normalization limits its provenance weight.
4. **PID 1 process/file-history mismatch.** MAC-MROSS-02 ES line 1 presents launchd start time `2026-10-06T13:00:00.000000Z` with executable birthtime/ctime `2026-10-29T09:40:49.455382268Z`. All four responses confirm or retain the observation while recognizing that filesystem metadata can be restored, altered or transformed. Eleven repeated actor snapshots are one historical concern, not eleven independent contradictions.

The strongest counterweight is the repeatedly successful native-field, identity, lifecycle, protocol and investigative-correlation checking. All reviewers retain that evidence; none interprets localized artifacts as globally crude telemetry.

## Most Debated Points

### Round 2 — Cross-Examination

**Same-flow correctness versus cross-leg conservation.** The apparent conflict between the Threat Hunter/Detection Engineer's favorable byte-budget checks and Network Forensics' finding is resolved by scope. HTTP/file payloads can fit their own connection while the two separate legs of a purported opaque relay disagree. Both initially inconclusive reviewers explicitly accepted that distinction in their revisions. The more targeted directional checks carry stronger weight for this particular proxy question; the favorable same-flow findings remain valid.

**How secure are proxy associations?** Reviewers checked nearby matching CONNECT/SNI activity with different windows: Detection used five seconds, Threat Hunter and Network used ten seconds, and Host/EDR used 60 seconds. Their reported uniqueness checks reinforce the cited examples without creating a durable identity link. Network's same-DMZ verification also addresses sensor-accounting/clock alternatives. The panel nevertheless leaves counter semantics, hidden additional legs and undocumented transformation unresolved. `SF` and zero missed bytes do not substitute for packet captures. Buffering or early closure can leave excess server bytes upstream; it does not explain the stronger opposite-direction deficits under the opaque-relay interpretation.

**Scheduled intent versus measured fork occurrence.** All four responses distinguish integer-second command schedules from kernel occurrence timestamps. Automation can schedule whole-second offsets, but the exact retained microsecond phases across distinct forks, also reflected in monotonic time, are what raised concern. An exporter that reconstructs both clocks could produce the pattern from real telemetry. Thus the panel treats it as timing texture, not an impossible lifecycle, and does not claim the two clock fields are independent evidence.

**Metadata uncertainty and double counting.** Shared deployment or transformed metadata can explain the midnight executable pattern; preserved/altered birth metadata can explain the launchd chronology. The reviewers consistently assign less weight to these than to the two leading concerns. They also recognize that multiple Mac anomalies could share one transformation cause.

**What was independently reproduced?** The 479 eligible sessions, 90 mismatches and 47 stronger directional failures remain Network Forensics' selected diagnostic results. Threat Hunter, Detection Engineer and Host/EDR explicitly did not reproduce that entire screen. Their revisions rely on directly checked examples. These counts are neither a panel-wide independent measurement nor a population failure estimate.

## Improvement Recommendations (Consensus)

All four individual responses support the following priorities, conditional on synthetic construction; the provenance/documentation alternatives also apply if the records are transformed real telemetry.

1. **Use authoritative directional opaque tunnel payloads across both legs and proxy counters.** Keep CONNECT setup/control bytes separate and add them only to the appropriate client-side accounting. Check that a completed, gap-free opaque relay cannot deliver more server bytes than its upstream supplied or send more client bytes upstream than its client supplied. Preserve legitimate buffering/abort asymmetries rather than requiring unconditional equality for every session.
2. **Make association and transformation semantics explicit.** Retain durable cross-leg identifiers where available, define counter scopes, and distinguish TLS inspection/transformation from opaque `tunnel` mode. If those semantics legitimately explain the examples, preserve them with the export so a hostname/time join is unnecessary.
3. **Resolve individual native fork occurrence times before rendering either clock.** Separate intended command schedules from actual occurrence timing, retain realistic execution/scheduling variation, and derive wall and monotonic clocks from the same resolved occurrence. Preserve correct identities and fork-before-exec order. Host/EDR additionally proposes a focused repeated-phase distribution check that allows genuine periodic scheduling and documented transformation; the shared recommendation is coherent occurrence ownership, not arbitrary unrelated jitter.
4. **Coordinate executable metadata with file, boot and process histories.** Preserve coherent repeated observations of the same file while avoiding an unexplained four-timestamp midnight default across unrelated applications. Keep long-running process histories compatible with associated executable history. Document intentional preservation, normalization or timestamp reconstruction rather than presenting transformed fields as unmodified native measurements.
5. **Preserve the demonstrated strengths while correcting those families.** Retain native event differentiation, process/session identities, transport-before-auth ordering and usable source correlations. The responses do not support adding arbitrary sources or weakening accurate correlations to make the data less readable.
