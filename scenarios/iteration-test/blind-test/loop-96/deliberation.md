# Deliberation Summary

This is a facilitator synthesis of the four supplied independent reports, not a new expert review or a transcript of participant discussion. No participant was recontacted, and no revised position is attributed to an expert. All verdicts, confidences and scores remain as submitted. No scenario, evaluation, repository or prior-run material was consulted; no additional data records were needed.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Recorded Verdict | Final Recorded Verdict Confidence | Final Recorded Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|------------------------|-----------------------------------|-------------------------------------|
| Threat Hunter | Inconclusive | 80 | 30 | Inconclusive | 80 | 30 |
| Detection Engineer | Real | 62 | 18 | Real | 62 | 18 |
| Network Forensics | Inconclusive | 78 | 30 | Inconclusive | 78 | 30 |
| Host/EDR Forensics | Inconclusive | 78 | 24 | Inconclusive | 78 | 24 |

“Final recorded” repeats the original submission; it does not represent a participant revision. The unweighted original mean synthetic-confidence is **25.5/100**: `(30 + 18 + 30 + 24) / 4`. The scores are expert assessments, not calibrated probabilities of origin. No post-deliberation mean was created.

Original category scores, preserved:

| Expert | Field format | Temporal | Cross-source | Behavioral | Environmental |
|--------|--------------|----------|--------------|------------|---------------|
| Threat Hunter | 9 | 8 | 9 | 8 | 8 |
| Detection Engineer | 9 | 8 | 9 | 8 | 8 |
| Network Forensics | 9 | 8 | 9 | 8 | 8 |
| Host/EDR Forensics | 9 | 9 | 9 | 8 | 8 |

## Round 1 — Findings Presented

- **Threat Hunter:** Inconclusive, confidence 80, synthetic-confidence 30. Twenty representative records and two exact pivots support feasible SCP/SSH and inspected-proxy upload sequences, including identity and source-port ownership. Decoding resolves the apparent Windows path-escaping issue. Scheduled sysstat command repetition is measurable but unscored because legitimate periodic work explains it.
- **Detection Engineer:** Real, confidence 62, synthetic-confidence 18. Eighteen representative records support native Windows field representations, an exact three-source process pivot, and internally consistent DNS transaction/packet accounting. Scoped hash-width checks and source distinctions are credible. The Real judgment is expressly tentative; these checks cannot certify provenance.
- **Network Forensics:** Inconclusive, confidence 78, synthetic-confidence 30. Nineteen representative records show coherent connection states and failed-handshake omissions; exact TLS/certificate and proxy tunnel pivots preserve identity, timing and accounting. The database sensor's 19 TLS rows have a narrow legacy distribution, a weak concern with a fixed-client alternative explanation.
- **Host/EDR Forensics:** Inconclusive, confidence 78, synthetic-confidence 24. Twenty representative records/commands support consistent Windows process ownership, transport-before-SSH-auth ordering, nonnegative matched process lifetimes and a credible macOS fork/exec distinction. Recurrent administrative process pairs on one workstation remain weak behavioral texture evidence.

The reported sample counts overlap across experts and must not be added as independent observations. Their aggregate checks likewise cover selected source populations, not an exhaustive adjudication of every record.

## Round 2 — Cross-Examination and Evidence Strength

### Real versus Inconclusive: provenance limit, not conflicting record evidence

All four reports describe the examined surface as predominantly production-like and identify no demonstrated high-impact contradiction. Detection Engineering selects Real with confidence 62 while explicitly acknowledging that a well-constructed synthetic collection could pass the same checks. The other three withhold production-origin attribution despite similarly favorable local findings. This is a difference in the threshold for a provenance verdict, not disagreement over an identified impossible record.

Exact joins establish usable shared identities and local consistency. They neither prove production origin nor become suspicious merely because they are complete. Likewise, lack of a detected defect in a bounded sample cannot certify the rest of the collection. Confidence in an Inconclusive verdict is distinct from confidence that records are synthetic.

### Encoding suspicion: resolved, no remaining defect

The Threat Hunter compared decoded eCAR and native Sysmon curl command lines: both are exactly 196 characters, equal, without doubled path separators. Displayed JSON escaping is not evidence of malformed Windows commands. The Host analyst's preliminary hash concern also disappears when executable hashes are restricted to Event 1 rather than conflated with module hashes in image-load rows. Neither observation warrants a repair or penalty.

### Repeated administrative tools: weak, unresolved texture question

The Host report counts explorer→PowerShell and explorer→mstsc nine times each, PowerShell→ssh and cmd→PowerShell eight times each among 118 Event 1 rows on one workstation. These counts can reflect real administration or collection selection. They do not establish duplicated detailed behavior, impossible user capability, unrealistic cadence or a generator fingerprint. The Threat Hunter's separate sysstat observation—two recurring command strings at 360 creations each out of 2,749—also has a straightforward scheduled-task explanation and was explicitly unscored. These are different populations and behaviors; their repetition is not mutually reinforcing proof of synthesis.

### Database TLS: small, explainable concentration

The Network report finds 19/19 database-sensor TLS rows using TLSv12: 11 CBC selections and eight GCM selections. The narrow distribution is worth testing against actual observed clients and destinations, but older fixed software can produce it. Broader core and DMZ TLS diversity does not refute a segment-specific fixed-client explanation. Without client inventory or negotiation details, the report supports only a weak signal, not a protocol impossibility or a requirement to modernize all connections.

### Source-specific blind spots and limits

Native Windows and Zeek representation checks are stronger within their inspected scope than claims about all platform schemas. Both endpoint-focused reports explicitly limit macOS version-specific certification. Network certificate metadata continuity does not establish signature validity or cryptographic trust. Source counts, sensor duplicates, selected event coverage and collection-window boundaries do not prove missing required evidence. None of these limits is promoted into a new synthetic indicator.

## Round 3 — Recorded Positions

No participant revisions were requested or obtained. The original four verdicts, verdict confidences, synthetic-confidence scores and category scores stand verbatim in the tables above. The facilitator does not simulate changed minds or recalculate scores from the cross-examination.

## Key Agreements

- The inspected cross-source pivots preserve concrete identities, tuples, account ownership and feasible ordering.
- Source-native distinctions and modest independent observation offsets are credible in the inspected Windows, Linux, Zeek and proxy records.
- No report establishes a hard contradiction, demonstrated required-companion gap or high-impact native-format defect.
- Positive local consistency does not establish production provenance; the bounded review leaves substantial unexamined scope.
- No corrective telemetry change is justified solely by these reports. Preserve the demonstrated correlations and source semantics.

## Key Disagreements

The only verdict split is one tentative Real versus three Inconclusive judgments. The reports do not disagree about a concrete defect. Host administrative repetition and database TLS concentration receive small concern in their respective specialty reports, while other reports do not independently adjudicate those exact populations. Absence of their endorsement is not a rebuttal or consensus upgrade.

## Most Convincing Evidence

Ranked by specificity of the documented check, not by strength of provenance proof:

1. **Exact Windows process identity:** PID 5180 / `0x143c`, parent 4356 / `0x1104`, `taskhostw.exe /Run`, SYSTEM/logon `0x3e7` agree across Sysmon Event 1 record 30326, eCAR line 17 and Security 4688 record 129968 on WS-AJOHNSON-01, with compatible source delays. Both Detection and Host reports document this pivot.
2. **Exact SSH transport and authentication relationships:** The Threat Hunter's `10.10.4.10:37862 → 10.10.2.30:22` SCP pivot connects source process identity, two network observations, target public-key auth and endpoint session login, followed by source process termination after transport closure. The Host report independently examines a different exact SSH tuple with FLOW preceding Accepted, PAM and endpoint LOGIN.
3. **Proxy transport and tunnel accounting:** The Network report's UID `CcWaxAYQjc7El3HI2J` and client port 38139 join CONNECT and inspected GET through tunnel `PT-2eaa7484f8d1ecf0`; control plus tunnel bytes reconcile to connection totals, and second-resolution request time fits the transport interval.
4. **TLS certificate reference continuity:** UID `CfXsGkkuG9lcJw887K` links connection and handshake; referenced leaf/intermediate FUIDs preserve SNI/SAN and issuer/subject agreement, appropriate CA flags and valid-at-observation intervals. This is metadata consistency, without a signature/trust claim.
5. **Source-native transaction and lifecycle checks:** Detection's DNS UID `ClnAf4xMznbwm13HlN` has coherent RTT/duration and per-packet IPv4/UDP accounting; Host's 86 exact matched eCAR process identities have no termination-before-creation inversion. These are scoped affirmative checks, not full-corpus guarantees.

## Most Debated Points

The reports support discussion of the provenance threshold, weak administrative repetition, and the small database TLS population. No actual participant debate occurred. The encoding and module-hash concerns are resolved checks, not open authenticity disputes. Complete joins, compact suspicious sequences, unavailable outside-window evidence and thin selected source coverage are not synthetic tells.

## Follow-up Recommendations

No defect-driven repair has panel support. The following are targeted investigations grounded in the specialty reports, not claims of participant consensus on new work:

1. Before changing Windows administrative behavior, compare exact command lines, user/session context, inter-arrival timing and host-specific workloads over a larger visible interval. Test whether repetition exceeds plausible repeated administration. Do not add arbitrary noise from parent/image counts alone.
2. Group the 19 database TLS rows by exact client, destination and available software/configuration evidence. Determine whether a stable legacy client profile explains the negotiated selections before changing cipher or version distributions. Do not replace all TLSv12 traffic based on this sample.
3. Retain source-specific process/tuple ownership, transport-before-auth ordering, proxy inspection/client-port context, packet accounting and independent observation timing. No repair to the documented joins is supported.

Do not invent new event families, pre-window creators, post-window terminators, policy effects or narrative stages to fill assessment limits. No narrative, attack completeness, source completeness or provenance-uncertainty penalty is added by this synthesis.
