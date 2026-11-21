# Deliberation Summary

This is a facilitator synthesis of the four original reports and all four actual individual deliberation responses. The reviewers reconsidered the original reports separately; this document does not represent a live discussion or attribute one reviewer's revised response to another. No additional authenticity findings are introduced.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 82 | 45 | Synthetic | 88 | 70 |
| Detection Engineer | Synthetic | 88 | 68 | Synthetic | 88 | 68 |
| Network Forensics | Inconclusive | 82 | 49 | Synthetic | 84 | 65 |
| Host/EDR Forensics | Inconclusive | 78 | 38 | Synthetic | 90 | 72 |

The arithmetic mean of the revised synthetic-confidence scores is **68.75/100**: `(70 + 68 + 65 + 72) / 4`. This is a descriptive mean of the four submitted scores, not an independently calibrated probability. All four final verdicts favor synthesis in the likely-synthetic band; none claims a demonstrated hard contradiction.

The original positions and strongest specialty observations were:

- **Threat Hunter:** Three RDP connections between the same endpoints lasted `887.865532`, `887.866576`, and `887.866366` seconds, a spread of 1.044 ms. A few irqbalance messages occupied roughly 23–33% of several Linux syslog streams. Against those concerns, the reviewer demonstrated workable account/SID, SSH, database extraction/staging, and explicit-proxy upload pivots, with no established impossible lifecycle.
- **Detection Engineer:** All nine examined nonterminal GUI launch triplets across both Macs had a second inter-event gap equal to twice the first within 1 µs; two native SSH shutdown chains had nearly exactly equal exit gaps. Broad JSON/XML parsing, Windows GUID/lifecycle checks, source-specific fields, network joins, and a Windows share/access/handle sequence otherwise held up. The fine-grained native timestamp arithmetic was this reviewer's distinctive contribution.
- **Network Forensics:** Clean normal-close TCP records repeatedly had both directional residuals `ip_bytes - bytes - 52*pkts` in `{4,8,12}`, with balanced core pair frequencies; 446 core consecutive positive DNS repetitions occurred before the prior minimum TTL expired. Protocol joins, TCP states, certificate identities, proxy control/error bodies, and long SSH transports were coherent. External recursive TTL aging was a specific counterexample to any blanket claim that caching was absent.
- **Host/EDR Forensics:** Recurring snapd desktop-integration messages appeared on apparent infrastructure servers; three workstations each had 76 Sysmon creates; some routine commands used package/client labels as systemd units. These were initially weak or explainable concerns. The distinctive positive checks included 927 Windows process matches agreeing on image, command, and parent, correct Type 7 unlock interpretation, Linux SSH staging, and native Mac fork/exec and executable-identity distinctions.

The submitted revisions were evidence-driven:

- **Threat Hunter:** Verdict changed from Inconclusive to Synthetic, verdict confidence rose 82→88, and synthetic-confidence rose 45→70. Direct verification of the Detection Engineer's nine launch equations and two SSH exit chains drove the change. Selected `mach_time` checks reproduced the proportionality; the reviewer explicitly treated wall and monotonic clocks as fields of the same observations rather than independent evidence. Verified TCP residuals provided smaller support.
- **Detection Engineer:** Verdict and both scores remained unchanged at Synthetic, 88, and 68. Rechecks retained the original Mac findings, including monotonic fields. The RDP durations and TCP residuals were independently reproduced, but their plausible alternatives and limited independence did not justify raising the score.
- **Network Forensics:** Verdict changed from Inconclusive to Synthetic, verdict confidence rose 82→84, and synthetic-confidence rose 49→65. Direct verification of the native Mac timing equations supplied evidence more specific than the original network-only texture concerns. The reviewer retained the positive network assessment and assigned smaller weight to the verified RDP interval repetition.
- **Host/EDR Forensics:** Verdict changed from Inconclusive to Synthetic, verdict confidence rose 78→90, and synthetic-confidence rose 38→72. Verified Mac timing equations exposed a relationship the initial lifecycle checks had not measured; Terminal/iTerm and service/bootstrap controls did not share the ratio. Verified TCP residual texture supplied additional limited support. The original process/session fidelity findings were retained.

## Key Agreements

- All four revised responses identify the **nine native Mac GUI launch timing equations** as the strongest evidence favoring synthesis. The observations concern fork→xpcproxy exec→application exec transitions for the same child PID, across seven applications and two hosts, rather than three unrelated process creations.
- All four accept the **two evenly spaced native SSH exit chains** as supporting timing texture. They preserve the valid child-before-parent ordering and recognize that these chains may share a cause with the launch timing pattern; the examples are not independent dataset-wide failures.
- The data retain substantial **functional and source-native fidelity**: process/session identities, Windows semantics, native Mac fork/exec distinctions, SSH stages, network joins, and proxy control-versus-data relationships remain convincing within the checks performed. Correct ordering and implausible substage timing can coexist.
- The confirmed TCP residual lattice is suggestive distribution texture, with legitimate header/option/ACK explanations still available. None of the responses converts the arithmetic into packet-level proof.
- No reviewer established an impossible lifecycle, source-native schema defect, or generator identity leak. Source omissions, slice boundaries, complete correlation, and a coherent hunting narrative were not treated as synthetic indicators.

## Key Disagreements

There is **no remaining categorical verdict split** in the actual revised submissions. There is a material difference in evidentiary weight and residual uncertainty: final synthetic-confidence scores range from 65 to 72. The Network Forensics reviewer remains most cautious; the Host/EDR reviewer gives somewhat more supporting weight to the verified TCP texture. The Detection Engineer declined to raise the original 68 because the added RDP and TCP observations remained explainable and were not fully independent. These are differences of degree, not conflicting findings.

The principal unresolved provenance alternative is **timestamp reconstruction during collection, sanitization, replay, or export of otherwise real activity**. The Detection Engineer additionally names an instrumented launch harness. All responses leave room for transformed production-derived activity; none establishes that such a transformation occurred. The repeated family-specific equations favor constructed timing in their judgments, but do not establish fabrication of every underlying action.

Weaker observations remain unresolved rather than promoted into consensus defects. Fixed session policy or automation can explain RDP duration repetition; application resolvers and retries can explain DNS repetition; shared images and collection policy can explain desktop components and irqbalance proportions; accidental count ties, failed commands, or custom units can explain the host concerns. No reviewer argues those alternatives were disproved.

## Most Convincing Evidence

The ordering below synthesizes the priorities expressed in the actual responses; it is not a separate panel vote.

1. **Nine GUI launch triplets obey `gap2 = 2 × gap1` within 1 µs.** This finding caused all three initially inconclusive reviewers to revise. Representative native lines are MAC-MROSS-01 32–34 (5,806 and 11,612 µs) and MAC-MROSS-02 22–24 (2,767 and 5,534 µs). Rechecked monotonic fields and nonmatching terminal/service controls weaken display-only or universal quantization explanations. Export/replay reconstruction remains viable.
2. **Two SSH shutdown triplets have nearly exactly equal exit gaps.** MAC-MROSS-02 native lines 74–76 have 147,109/147,109 µs gaps; MAC-MROSS-01 lines 108–110 have 331,275/331,276 µs gaps. All reviewers treat these as supporting the same broader timing concern, with correct lifecycle order.
3. **Restricted, balanced TCP overhead residuals.** The stated `{4,8,12}` pattern covers 1,923/3,735 core, 116/204 database, and 2,452/4,691 DMZ qualifying records; core pair counts range 193–233. Rechecks confirm the observation. The exploratory 52-byte baseline, valid stack behavior, and overlapping sensor views limit its weight.
4. **Substantive relationship-level realism.** The 927 agreeing Windows process matches, checked lifecycle bounds, coherent SSH stages, protocol tuples, certificate identities, and proxy body/control accounting constrain the severity of the authenticity assessment. These positives demonstrate plausible operational evidence, while leaving provenance unresolved.
5. **Three RDP durations within 1.044 ms.** The records are reproducible, but concern one endpoint pair and reconnecting-session behavior; timeout/policy explanations remain credible, and the third record includes capture loss. The responses consistently rank this below the Mac equations.

## Most Debated Points

- **Fine timing versus valid lifecycle:** Initial process/identity checks did not test proportional substage latency. The reviewers' revisions resolve this apparent friction by retaining both results rather than retracting the lifecycle positives.
- **Timing artifacts versus synthetic provenance:** Ordinary scheduling or a universal precision rule does not readily explain the scoped nine-launch equation, while reconstructed or instrumented production-derived timestamps could. The responses favor synthesis without claiming that alternative was excluded.
- **TCP texture versus packet validity:** A verified residual calculation is not a verified invalid packet model. The narrow balanced distribution invites comparison to real segment/header/ACK behavior; it does not establish a protocol contradiction.
- **RDP interval reuse versus legitimate timers:** The unusual repeated interval is weaker evidence because of its single endpoint pair, session/reconnect context, and capture-loss caveat. The reviewers caution against altering genuine policy timing just to make it less regular.
- **Environmental repetition versus collection/image context:** DNS retries, IRQ verbosity, server desktop packages, tied counts, and unit-name mistakes remain low-specificity observations. Stronger Mac evidence does not retrospectively make these weak clues decisive. The isolated unjoined SMB mapping also does not conflict with the network reviewer's narrower SMB-file join check and receives no synthetic-score weight.

## Improvement Recommendations (Consensus)

These recommendations are conditional on the data being synthetic and are supported by all four individual deliberation responses:

1. **Model GUI launch stages with separate conditional latency components.** Preserve launchd fork→xpcproxy→application causality, executable identity, and native/normalized distinctions, while removing the repeated proportional equation. Check the cited family across applications and hosts; a constant offset to the entire chain does not address its interval relationship.
2. **Model SSH shutdown as dependent, individually varying waits.** Give shell, intermediate SSH child, and supervisor completion their own causal delays while preserving child-before-parent behavior, rather than dividing a shutdown interval into equal steps.
3. **Validate TCP accounting against packet-derived or measured stack behavior.** Compare the stated bidirectional residual lattice and pair frequencies with actual segment/header/option/ACK examples. Correct a modeling mechanism if demonstrated, while retaining valid fixed overhead, byte bounds, and sensor visibility assumptions.
4. **Preserve the demonstrated identity and lifecycle strengths.** Retain process/session agreement, Windows unlock semantics, native Mac fork/exec and signing/file identity, SSH transport/auth/session ordering, and proxy control/data accounting. The responses do not support adding arbitrary telemetry or out-of-window initiators to conceal the timing pattern.

Most responses also explicitly recommend checking the repeated RDP interval against intended timeout/reconnect policy before changing it; the Host/EDR response likewise cautions against randomizing valid policy timers. DNS resolver attribution and cache-aware modeling, Linux image/role membership, source proportions, and command/unit vocabulary remain targeted lower-confidence follow-ups, not established consensus defects or justification for arbitrary extra noise.
