# Deliberation Summary

This facilitation synthesizes the four original reports and the four actual individual deliberation responses. It adds no fifth expert opinion, new inspection, invented exchange, vote, or score. The initial split was two Synthetic and two Real assessments; all four submitted final responses assess Synthetic, with qualifications. The shared reason is endpoint timing texture in otherwise technically coherent telemetry, not a demonstrated impossible lifecycle or a provenance leak.

## Panel Composition

All values below are copied from the corresponding expert's submissions and are on a 0–100 scale. Verdict confidence and synthetic-confidence are separate measures; neither is inferred from the other.

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 72 | 62 | Synthetic | 87 | 74 |
| Detection Engineer | Real | 62 | 28 | Synthetic | 79 | 66 |
| Network Forensics | Real | 66 | 29 | Synthetic | 76 | 64 |
| Host/EDR Forensics | Synthetic | 86 | 70 | Synthetic | 90 | 74 |

## Round 1 — Present Findings

### Threat Hunter

The initial Synthetic assessment (72 verdict confidence; 62 synthetic-confidence) rested on native Windows session-bootstrap timing: ten of 16 parent-GUID-linked smss.exe → winlogon.exe pairs fell within 499–501 ms across five hosts, including eight exactly 500 ms. These are instances of one finding, not ten independent defects. The other six intervals range from 140 to 1,445 ms.

The strongest counterevidence was coherent investigative activity and bounded lifecycle checks: the database dump/compression/scp/SMB trail, Windows service installation versus SYSTEM execution identity, and endpoint-to-proxy uploads all supported practical hunting. The hunter's distinctive contribution was following these account and file boundaries without conflating download with execution, local root with directory credentials, or installer identity with service execution identity. No tested visible process-identity inversion was found.

### Detection Engineer

The initial Real assessment (62; 28) emphasized source-native semantics and identities: Security hexadecimal PIDs versus Sysmon decimal PIDs, Type 3 logon/share/logoff LUID continuity, event-specific Windows fields, macOS fork-versus-exec distinctions, and valid visible lifecycle/transport ordering. Security 1102's Eventlog provider and UserData shape were a particularly specific native observation.

The main reservation was one unmatched SMB mapping UID, `ClGQ20XvLARdhEcASSd`, among 14,614 inspected protocol records. The engineer treated it as a weak unavailable SIEM join with possible collection-boundary or filtering explanations, not a proven generation defect. Expected ten-minute sysstat scheduling was explicitly accepted as operational repetition.

### Network Forensics

The initial Real assessment (66; 29) rested on sensor-specific roles and outcomes; coherent DNS→TCP→TLS examples, HTTP/proxy leg semantics and byte budgets; and passive TLS visibility and certificate identity checks. In particular, none of the 2,411 TLS 1.3 SSL observations exposed a certificate-chain FUID list, while inspected TLS 1.2 evidence and key/cipher relationships remained coherent.

The reservation was a weak duration-tail concern: 2,955 successful DMZ HTTP observations had a minimum duration of 0.458486 seconds and 3,305 successful DMZ SSL observations a minimum of 0.828989 seconds. Proxy/application behavior, selection and close policy could explain these minima. The analyst distinguished overlapping sensor observations from unique activities and sequence-derived payload accounting from captured IP bytes.

### Host/EDR Forensics

The initial Synthetic assessment (86; 70) primarily rested on three groups of repeated six-digit fractional anchors in native macOS shell forks: ten of 59 visible shell-parented forks across two Macs. Subsequent exec timestamps varied individually, making file-wide coarse precision an inadequate explanation. Repeated cat/tee handling of binary documents added modest behavioral weight, with explicit acknowledgement that those commands can validly read or write binary bytes.

Strong counterevidence included 927/927 Sysmon process creations matching Security by PID, image and command; stable executable identities; no tested parent/process lifetime inversion; layered Linux SSH timing; and correct macOS fork, successive exec, pidversion and exit semantics. The host specialist carefully separated an AppleSystemPolicy message from an enforcement outcome and plist file observations from activation or execution.

## Round 2 — Cross-Examination

### Native correctness versus temporal texture

The initial disagreement concerned evidentiary weight rather than incompatible observations. Detection and Network initially gave more weight to correct source semantics and the absence of demonstrated contradictions. Host/EDR and the hunter gave more weight to recurring native timing concentrations. In their actual revisions, Detection and Network accepted that their initial checks did not test this distributional question. Correct schemas, byte budgets and causal identities can coexist with an authored timing schedule. Those working contracts remain substantial counterevidence and were not withdrawn when the verdicts changed.

### macOS timing: strongest shared influence, with automation alternatives

The cited fork groups are MAC-MROSS-01 native lines 35/38/41/44 at `13:48:41.198588000`, `13:49:08.198588000`, `13:49:43.198588000`, and `13:50:02.198588000`; lines 53/56/59 repeating `.487145000`; and MAC-MROSS-02 lines 86/89/92 repeating `.965208000`. All are UTC on 2026-11-02. These are distinct children and commands. All three other experts report independently checking the host finding in their deliberation responses.

Host/EDR and the hunter also report that the first group's mach_time differences are 648,000,000, 840,000,000 and 456,000,000 ticks, corresponding to the 27-, 35- and 19-second wall-clock gaps at the observed scale. This weakens a display-format-only explanation; it does not establish an impossible clock or prove generation.

All four retain automation, replay/scheduling or timestamp transformation as viable alternatives. Shell histories without a visible wrapper do not prove manual interaction or exclude an unseen scheduler. No submitted response supplies a production comparison or a documented transformation that resolves this. The repeated native groups are one timing finding, not separate independent findings for history, exec, monotonic time and normalized telemetry.

### Windows timing: reproduced concentration, narrower interpretation

The three other reviewers report reproducing the hunter's complete GUID-linked distribution in milliseconds:

`140, 363, 499, 500, 500, 500, 500, 500, 500, 500, 500, 501, 1004, 1173, 1225, 1445`.

Host/EDR adds an important qualification: the 500 ms concentration is in native process-occurrence UtcTime at millisecond precision. Higher-precision System/TimeCreated observation fields do not universally preserve exact half-second gaps. For example, the third DC-01 pair's observation times are `18:10:09.9044447Z` and `18:10:10.4212687Z`, while its UtcTime gap is 500 ms. The finding must not be expanded into a claim that every timestamp is copied or describes identical latency.

Common Windows implementation behavior, timer boundaries or collection transformation remain possible. All four retain this as distribution_texture, not hard_contradiction. The hunter explicitly declines to assume that the Windows and macOS patterns have statistically independent causes.

### Apparent SMB conflict resolved by coverage

Detection's unmatched SMB mapping does not contradict Network's original successful joins: Network's enumerated SMB checks covered smb_files, whereas the unmatched row is in smb_mapping. Network and the hunter report confirming the row during deliberation. All retain slice boundaries, long-lived connections or filtering as alternatives. None promotes it into a proven impossible relationship or a significant reason for the final verdict.

### Weak signals remain weak

The HTTP/TLS duration minima are not established artificial floors: connection lifetime is not request latency, and proxy close policy, transaction selection and application behavior remain plausible. Shared core/DMZ observations are not independent confirmations. The final score changes do not depend on accepting this as a confirmed defect.

Binary-document cat/tee activity remains modest evidence for Host/EDR and receives little or secondary weight from the other three. Descriptor redirection, transfer, scripting and inspection can explain it; argv does not establish intent or stdout destination. No reviewer treats it as impossible file handling.

## Round 3 — Actual Revised Positions

| Expert | Actual change | Submitted reason |
|--------|---------------|------------------|
| Threat Hunter | Synthetic retained; verdict confidence 72→87; synthetic-confidence 62→74 | Independently confirmed macOS forks, denominator and monotonic intervals broadened the basis beyond the original Windows mode. Working lifecycles and collector alternatives continue to limit certainty. |
| Detection Engineer | Real→Synthetic; verdict confidence 62→79; synthetic-confidence 28→66 | Reproduced both endpoint timing concentrations, with macOS the largest influence. Original schema/lifecycle checks remain favorable. The engineer specifically revised temporal realism from 9/10 to 6/10 while keeping native-format and correlation judgments approximately 9/10. |
| Network Forensics | Real→Synthetic; verdict confidence 66→76; synthetic-confidence 29→64 | Rechecked the native macOS and Windows patterns. The macOS finding outweighed the initial reliance on network consistency for overall provenance. The network-only assessment remains largely production-like. |
| Host/EDR Forensics | Synthetic retained; verdict confidence 86→90; synthetic-confidence 70→74 | Reproduced the Windows concentration as an additional timing family; macOS remains primary. Rechecked mach_time and preserved the distinction between occurrence and observation timestamps. |

No expert reports withdrawing the core timing observations. No final values are facilitator estimates. The submitted revisions increase confidence without claiming a hard contradiction or entering the 81–100 synthetic-confidence band.

## Round 4 — Consensus Summary

### Key Agreements

- All four actual final verdicts are qualified Synthetic. Their final synthetic-confidence scores range from 64 to 74, while verdict confidence ranges from 76 to 90.
- Repeated macOS fork anchors are the strongest shared synthetic indicator; the Windows bootstrap concentration provides additional support. Both concern distribution texture rather than impossible source events.
- Native fields, process/session identities, source-specific observations, network accounting and investigated causal chains remain credible. Technical realism does not prove production provenance, and a Synthetic verdict does not imply unusable detection telemetry.
- The unmatched SMB mapping, network duration tails and document-command behavior do not carry the decisive weight of the timing findings.
- A documented production timestamp transformation or actual scheduler/implementation explanation could materially weaken the synthetic inference.

### Key Disagreements

There is no remaining disagreement in the submitted final verdict labels. Residual differences concern strength and specialty scope: Network retains a largely production-like network-only interpretation and the lowest final synthetic-confidence, 64; Detection assigns 66; Host/EDR and the hunter assign 74. Host/EDR retains modest weight for repeated document commands, whereas the other three give it little or secondary weight. The submissions do not establish a common quantitative weighting or a panel probability, and none is invented here.

### Most Convincing Evidence

The following ordering reflects the emphasis in the submitted responses, not a separate ranked ballot:

1. **Synthetic direction — macOS fork anchors:** three groups, ten of 59 shell-parented forks, with distinct children/commands and individually varying exec offsets; monotonic intervals support that it is not merely a UTC display artifact. This was the principal new influence on both Real→Synthetic changes and the hunter's increase.
2. **Synthetic direction — Windows bootstrap concentration:** ten of 16 GUID-linked smss→winlogon intervals at 499–501 ms across five hosts, eight exactly 500 ms. All reviewers reproduced it, while preserving implementation/collection alternatives and timestamp-field distinctions.
3. **Realism counterweight — endpoint identities and lifecycles:** all 927 visible Sysmon creations matched Security in the host review; bounded process/parent/session checks found no demonstrated impossible inversion, and macOS fork/exec semantics remain coherent.
4. **Realism counterweight — network/source semantics:** tested DNS/transport/TLS ordering, proxy-leg distinctions, payload and certificate budgets, passive TLS visibility and sensor-specific observations remain coherent. Network's stated SMB file coverage must not be expanded to every mapping record.

### Most Debated Points

- Whether a shared timing anchor indicates an authored schedule or real automation/transformation; the files do not conclusively distinguish those explanations.
- Whether the Windows half-second mode is generated timing or native implementation behavior; a matched production reference is absent.
- Whether passing consistency checks should dominate provenance judgment; Detection and Network explicitly changed that weighting after checking endpoint texture.
- Whether duration tails, one missing connection reference and repeated binary-document commands justify repair; the panel keeps these conditional and low weight.

### Withdrawn, Rejected or Limited Evidence

No submitted response explicitly withdraws a previously scored core observation. Several stronger interpretations are explicitly rejected or restricted and must not be resurrected as panel findings: no proved hard lifecycle/schema contradiction, impossible binary handling, denial-versus-success outcome for MeetingAssist, plist activation from file presence, or impossible local shell use merely because an ssh child remains alive. Bare shell-history exit ordering and expected sysstat periodicity are also not scored contradictions. The Windows concentration is not asserted for all high-precision observation fields. The unmatched SMB row is not a universal transport-join failure, and favorable matching is not itself evidence of synthesis.

### Improvement Recommendations (Consensus)

1. **If synthetic, realize individual macOS command execution times before producing native fork/exec observations.** Avoid carrying one fractional anchor through separate integer-second command offsets unless an explicit modeled scheduler warrants it. Preserve valid identities, fork→exec→exit ordering and source timing; independent rendered-row jitter would risk the existing correlations. All four support this priority.
2. **Validate Windows session-bootstrap timing against comparable host/session/collector behavior.** Investigate the measured 499–501 ms concentration and model evidence-based session timing if it is generated. Preserve parent GUID and causal/session relationships; regularity alone does not justify arbitrary noise. All four support this direction.
3. **If production-derived timestamps were transformed, document the actual transformation or scheduler and its scope.** Explain retained fractional and monotonic anchors, the cross-host Windows mode and the differing remaining intervals. All four identify such evidence as material to their qualified inference.
4. **Preserve the established technical strengths.** Keep native event distinctions, stable process/executable identities, account boundaries, lifecycle ownership, transport accounting and sensor-specific observation behavior. The reviews do not justify degrading successful joins or adding missingness to make the data appear less coordinated.

The remaining suggestions are conditional rather than equally supported priorities: compare HTTP/TLS lower tails with a matching proxy/application workload and its close policy; retain the owning SMB connection only when the intended collection policy requires it; and model document-access purpose and descriptor context where cat/tee is used. Do not fabricate a transport row solely to satisfy the isolated join. Host/EDR chiefly advances the document-behavior recommendation; the other reviewers preserve its alternative explanations and low weight.

### Methodological Limitations

The facilitator read only the deliberation instructions and eight submitted reviewer documents in this study directory. All dataset observations and reported rechecks above are attributed to those submissions; the facilitator did not inspect original logs, repository content, scenario, ground truth, parents or outside reference data.

The reviewers describe a six-hour daytime slice around 13:00–19:00 UTC on 2026-11-02, with selected sources and bounded consistency tests rather than proof of comprehensive collection. Pre-window processes/connections/sessions, post-window termination, selective Sysmon coverage and sparse Unified Log coverage are not defects by themselves. This window cannot establish weekend or overnight realism. Network sensor counts include overlapping observations rather than independent activities; normalized/native views likewise do not multiply an underlying finding. Rechecking a peer's cited evidence improves verification, not the number of independent discoveries.

The deliberation responses were written after exposure to the same four initial reports. They are actual individual revisions, not a recorded live discussion or a second blind study; convergence must not be treated as four independent provenance experiments. No formal null model, chance probability, matched production distribution, proved transformation or statistically independent causal mechanism is established. The scores are the reviewers' judgments, not calibrated probabilities. Sanitized names, filesystem copy timestamps, collection completeness, ease of attack narration and successful cross-source matching are not used as synthetic indicators.

## Source Documents

- `threat-hunter-report.md` and `threat-hunter-deliberation.md`
- `detection-engineer-report.md` and `detection-engineer-deliberation.md`
- `network-forensics-report.md` and `network-forensics-deliberation.md`
- `host-forensics-report.md` and `host-forensics-deliberation.md`

Structure follows `deliberation-instructions.md`.
