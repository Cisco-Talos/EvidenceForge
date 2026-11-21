# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 82 | 48 | Synthetic | 79 | 64 |
| Detection Engineer | Synthetic | 78 | 62 | Synthetic | 82 | 65 |
| Network Forensics | Real | 61 | 27 | Synthetic | 76 | 64 |
| Host/EDR Forensics | Inconclusive | 78 | 34 | Synthetic | 76 | 63 |

The initial Synthetic-Confidence mean is **42.75**: `(48 + 62 + 27 + 34) / 4`. The actual final mean is **64.00**: `(64 + 65 + 64 + 63) / 4`. These are separate descriptive means, not probabilities of provenance or percentages of defective records. Verdict confidence is a distinct measure.

This summary uses the four original reports and four actual deliberation responses. The analysts each read the original reports and submitted their own revised position; they did not read one another's revised responses. The final agreement below is observed convergence across those responses, not a claim that a joint vote or further discussion occurred. No additional data findings are introduced here.

The initial specialty contributions were:

- **Threat Hunter:** Windows 4688 creator/target identity treatment was the main reservation; direct SCP FLOW attribution was weaker. Positive evidence included workable credential boundaries, SSH transport/authentication order and appropriate HTTPS CONNECT visibility. The hunter uniquely emphasized the practical investigation paths and benign support/encoded-command comparisons.
- **Detection Engineer:** Three groups of exact native Mac fork phases drove the initial Synthetic judgment. Full structured-file parsing, 990 checked Sysmon parent relationships and protocol/connection consistency were counterweights. Source-specific 1102 log-clear rendering and record-number reset were distinctive positive observations.
- **Network Forensics:** Varied connection outcomes, protocol accounting, DNS failures and compatible TLS/certificate relationships supported the initial Real preference. One microsecond-spaced HTML/stylesheet request pair was weak counterevidence. DHCP renewal timing and detailed proxy control/tunnel distinctions added network-specific support.
- **Host/EDR Forensics:** Stable Windows hashes/parentage, coherent process dependencies and matched SSH transport-before-authentication favored plausibility. Unusual Mac executable sizes and concentrated Linux daemon messages were qualified reservations. Distinct Terminal/iTerm2 fork/exec trees and policy-warning-versus-execution interpretation were specialty contributions.

## Key Agreements

- All four actual final assessments are **Synthetic**, with Synthetic-Confidence scores of 63–65. Each identifies the same localized Mac fork-timing pattern as the principal indicator, independently reproduced in their reported rechecks. The hunter, network analyst and host analyst changed verdict after considering this detection-engineering finding; the detection engineer retained Synthetic and increased confidence modestly.
- Ten of 102 native fork notifications form three repeated fractional-time groups across two Macs. Separate children retain exact microsecond phases over integer-second command gaps while subsequent exec delays vary. All four treat this as **one recurring distribution-texture family**, not ten independent contradictions.
- The broad operational strengths remain intact: checked process lifecycles and parent relationships, matched SSH transport/authentication ordering, source-specific schemas, and feasible network/proxy relationships. The revised endpoint timing concern does not negate the network analyst's original protocol findings.
- No analyst establishes a hard contradiction, generator identity leak or pervasive collapse of realism. Scheduled automation and transformed/retimed exports remain possible alternatives to synthetic construction.
- Windows identity interpretation requires effective requesting-token evidence; SCP attribution requires a collector ownership definition. The isolated HTTP micro-gap, unusual binary sizes and daemon concentrations do not warrant strong independent penalties.
- Strong matching, sanitized domains, narrative coherence, optional missing families and out-of-window initiators are not themselves synthetic indicators. Arbitrary gaps or lifecycle errors would not remedy the demonstrated concern.

## Key Disagreements

There is no remaining disagreement in final verdict, but the supporting weights differ.

**Windows 4688 semantics are the clearest unresolved difference.** All analysts reproduce 992 records with null target SID/logon ID fields and 49 matched parent/child account differences. Detection Engineering, Network Forensics and Host/EDR retain a modest, qualified contract-gap concern; the hunter explicitly downgrades the original materially scored concern to a weak unresolved attribution question. The `/netonly` example changes LUID from runas `0x26db422` to child cmd `0x27c990d`, which 4688 places in SubjectLogonId with empty targets. This supports examining child-versus-creator mapping, but parent ownership does not reveal the effective requesting thread token. None calls the 49 cases proven invalid events.

**The initial Real preference was narrowed by new inspection scope, not refuted by bad network mechanics.** The network analyst moved from Real/61/27 to Synthetic/76/64 after confirming the Mac timing pattern and Windows screening evidence, while preserving the original favorable DNS/TLS/accounting conclusions. The other final responses likewise say correct lifecycles can coexist with a localized occurrence-time artifact.

The hunter's verdict confidence decreases 82→79 and the host analyst's 78→76 despite their directional changes; their actual responses retain substantial alternative-explanation uncertainty. Detection Engineering increases 78→82, and Network Forensics increases 61→76. These are the submitted confidence changes, not a uniform confidence gain inferred from unanimity.

## Most Convincing Evidence

The ordering below reflects the emphasis shared in the actual responses; the panel did not supply a formal ordinal vote.

1. **Synthetic: repeated native Mac fork phases.** MAC-MROSS-01 ES lines 35/38/41/44 preserve `.198588000` at 13:48:41, 13:49:08, 13:49:43 and 13:50:02; lines 53/56/59 preserve `.487145000`. MAC-MROSS-02 lines 86/89/92 preserve `.965208000`. In the first group, mach-time increments encode exactly 27, 35 and 19 seconds at the observed 24-million-tick/second relationship; child start times retain the phase, while fork-to-exec delays vary. All four regard this as materially stronger than generic regularity, though physically possible and localized.
2. **Plausibility counterweight: coherent visible endpoint lifecycles and identities.** Reported population checks find no demonstrated relevant process-order inversion within their stated allowances; known parent metadata, process hashes and native fork/exec distinctions remain consistent. Detection Engineering also reports 794 paired Sysmon lifetimes without integer-second lifetimes. These constrain any claim of widespread timestamp or lifecycle failure without proving real provenance.
3. **Plausibility counterweight: sound protocol and accounting relationships.** Network and detection reviews report compatible connection tuples/intervals, TLS/cipher/key relationships, HTTP body accounting and varied state/loss outcomes. Other responses retain these strengths and matched SSH transport-before-authentication evidence. One absent SMB connection companion remains compatible with selective observation and unscored.
4. **Qualified synthetic support: Windows creator/target mapping pattern.** The recurring null-target population and specific userinit and runas/LUID examples attract modest support from three final responses. The hunter lowers its weight. Effective-token and export semantics prevent a native-violation conclusion; this is substantially weaker than item 1.

## Most Debated Points

- **Precision artifact versus real scheduling/export transformation:** exact phase retention in independent native fork wall/monotonic/start times, alongside variable exec delays, persuades all four. Controlled scheduling or reconstructed timestamps remain viable alternatives; the supplied records do not establish those semantics. Correct ordering alone does not resolve authenticity.
- **Creator, parent and new-process identities:** consistent Sysmon parent fields and questionable Security subject assignment can coexist. Impersonation, brokers and same-local-user/new-LUID semantics weaken simple parent-account comparisons. The hunter's explicit downgrade is an important limit on the apparent corroboration.
- **One-microsecond HTTP request gap:** DMZ HTTP lines 344–345, UID `CUndz3AFi0yhIEnnis`, differ by exactly one microsecond, with the core counterpart reproducing it. All retain low weight because referrer linkage does not prove fresh HTML discovery; cached knowledge, preloading/pipelining or timestamp adjustment remain explanations. Two sensors observe one underlying page load, one of 19 multi-request connections.
- **SCP process attribution:** DB-PROD-01 eCAR line 616 assigns the port-35881 SSH flow to scp PID 1418126 without a visible SSH child. Literal socket ownership and initiating-ancestor attribution yield different interpretations. All leave the collection contract unresolved and preserve favorable transfer evidence.
- **Host texture:** unusual uname/ps/ssh/launchd sizes need matching binary/build evidence; daemon shares of 47.1–57.7% can follow verbosity, filtering or faults. The host analyst expressly retains these as low-priority reservations, and the others decline to turn them into substantial additional evidence.

## Improvement Recommendations (Consensus)

- **Highest priority; all four:** if synthetic, assign each distinct native fork a plausible occurrence time instead of copying a group anchor's fraction through integer-second command offsets. Keep child start times, wall/monotonic clocks, actor identities and fork/exec/exit ordering coherent. Changing only the rendered wall-clock field would leave the same issue elsewhere. Detection Engineering additionally recommends a targeted repeated-phase check across distinct children that permits genuine shared timestamps and coarse source precision.
- **All four, with different evidentiary weight:** verify Windows requesting-thread identity, parent identity and child token separately, especially userinit and runas/new-credentials transitions. Correct 4688 creator/target mapping where native capture semantics support the distinction; do not assume every parent/child account difference or null target is wrong.
- **All four:** establish whether normalized FLOW process attribution means socket owner or initiating ancestor before changing SCP evidence. Model the SSH child if the intended contract requires literal ownership, rather than inferring a defect solely from an unobserved process.
- **Three final responses explicitly recommend this:** investigate the isolated HTML/stylesheet micro-gap against actual request scheduling or export processing. Preserve legitimate caching/speculation and varied browsing delays; avoid imposing a fixed delay on every page load. Host/EDR also confirms the observation's low evidentiary weight but does not separately prescribe this repair.
- **All four:** preserve the existing source-specific visibility, protocol/certificate accounting, credential distinctions and lifecycle discipline. Random missingness, orphan events or contradictory timings would not address the observed issue.

Mac binary-size verification and Linux daemon-policy calibration remain conditional, lower-priority suggestions from the original host report. The actual responses do not establish either as a consensus requirement to alter the observed values or source mix.
