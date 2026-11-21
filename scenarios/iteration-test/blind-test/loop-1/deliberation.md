# Deliberation Summary

## Scope and Facilitation

This summary uses only the supplied deliberation instructions, four original `*-report.md` files, and four actual `*-deliberation.md` responses. The facilitator did not inspect the dataset, repository, scenario, parent discussion, or history, and contributes no fifth authenticity vote. Checks described below were reported by the reviewers; they were not independently performed by the facilitator. Original and revised positions remain distinct.

The final panel assessment is unanimous **Synthetic**, with individual synthetic-confidence scores **78, 78, 80, and 80**. This consensus concerns the evidence of constructed content, principally the advertised DKIM keys. It does not establish that every surrounding observation was generated, that the data has impossible lifecycles, or that most records are defective. No composite panel score is substituted for the individual votes.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 85 | 43 | Synthetic | 94 | 78 |
| Detection Engineer | Inconclusive | 84 | 38 | Synthetic | 94 | 78 |
| Network Forensics | Synthetic | 96 | 78 | Synthetic | 97 | 80 |
| Host/EDR Forensics | Synthetic | 80 | 64 | Synthetic | 96 | 80 |

Verdict confidence and synthetic-confidence are separate reviewer measures. Neither measures the percentage of defective records. No revised category realism scores were supplied, so this summary does not invent them.

## Round 1 — Presented Findings

### Threat Hunter

Initial position: **Inconclusive / verdict confidence 85 / synthetic-confidence 43**.

- Broad visible process-boundary checks across 39,336 eCAR rows and 12,197 Sysmon events found no matched process use outside its visible lifetime under the stated 5 ms tolerance and collection-window exclusions.
- The DB-PROD export/gzip/scp chain, matching APP-INT receiver, and subsequent SMB staging supported feasible investigation pivots. A multipart upload preserved distinct proxy legs, request URI forms, and the same 1,573,258-byte body.
- Seven Mac binary-document reads through `cat` and short support-command fractional-second alignments were reservations with plausible script, selection, or measurement explanations.

Specialty contribution: distinguishing observed download, execution, transfer, and credential use from unsupported claims about success or authorization; preserving local versus outbound identities for `runas /netonly`; reconstructing practical SSH/SMB/proxy pivots without treating narrative completeness as an authenticity signal.

### Detection Engineer

Initial position: **Inconclusive / verdict confidence 84 / synthetic-confidence 38**.

- Source-specific Windows shapes were credible across 19,405 Security events and 12,197 Sysmon events. Event 1102 used the distinct Eventlog provider and `UserData/LogFileCleared` payload, with a record-counter reset.
- Checks covering 972 Sysmon creations and 815 terminations found no tested identity or lifecycle contradiction. Protocol joins across 23,842 Zeek connections showed no tested tuple or interval contradiction within the stated tolerances.
- Two native 4800/4801 intervals were approximately 0.318 ms and 0.956 ms. These were moderate local timing concerns, with software-triggered transitions or event-publication effects remaining alternatives.

Specialty contribution: event-specific provider/payload validation, hexadecimal versus decimal PID relationships, distinction between activity and publication timestamps, and conservative handling of reserved LUIDs, unmatched records, and collection boundaries.

### Network Forensics

Initial position: **Synthetic / verdict confidence 96 / synthetic-confidence 78**.

- Nine of twelve distinct advertised 2048-bit DKIM RSA public keys had tiny prime divisors after TXT reconstruction, base64 decoding, DER parsing, and trial division. This was the dominant adverse finding.
- Network behavior otherwise held up: varied connection outcomes, matching protocol/transport identities, certificate/file references, TLS 1.3 certificate-visibility limits, and separate CONNECT control-message versus tunnel byte scopes.
- Thirty-four of thirty-five background TXT queries across nineteen clients occurred in roughly twenty-three minutes of the six-hour window. A scheduled diagnostic task could explain this; it received little weight.

Specialty contribution: examining cryptographic answer contents beneath valid field syntax; distinguishing unique keys from repeated sensor observations; accounting for `missed_bytes` before rejecting apparent byte inconsistencies.

### Host/EDR Forensics

Initial position: **Synthetic / verdict confidence 80 / synthetic-confidence 64**.

- The same two collapsed workstation lock intervals, together with earlier same-session Type 7 authentication/eCAR observations, initially supported a `contract_gap` interpretation and drove the synthetic verdict.
- Stable process GUID/PID/image and hash relationships, coherent checked parentage and lifetimes, and platform-specific Linux SSH and macOS fork/exec behavior supported substantial endpoint realism.
- Seven native Mac `cat` executions against PDF/Office paths were a weak behavioral reservation, not an impossible command/file relationship.

Specialty contribution: comparing native lock-state records with authentication and normalized observations, checking executable identity continuity across macOS PID-version changes, and avoiding claims of application execution or activation from a policy message or plist placement alone.

## Round 2 — Cross-Examination

### Apparent contradiction: credible schemas versus defective DKIM contents

The initial inconclusive reports did not test DKIM moduli. Their positive parser, process, and transport checks therefore did not contradict the network result. During deliberation, the Threat Hunter, Detection Engineer, and Host/EDR reviewer each reported independently reproducing nine affected keys among twelve distinct decoded keys. The network reviewer also reported a second extraction method reproducing representative divisibility witnesses.

The reviewers converged on strong `distribution_texture` evidence: valid DER can contain a cryptographically implausible integer, and DNS can publish arbitrary content. This is not an impossible ASN.1 or DNS value. Independent reproductions strengthen confidence in the same finding; they do not create multiple independent defect families.

The strongest alternative is replacement of public-key contents during sanitization. Deliberately broken published keys or test/deception content are also possible. Domain-name sanitization alone does not explain modulus factors, and the reviewers reported no supplied evidence establishing key-content replacement. They therefore retained the finding while withholding certainty about the provenance of every surrounding record.

### Genuine interpretive disagreement: lock-state anomaly versus demonstrated contract gap

All reviewers accepted the native submillisecond lock intervals. The original Host/EDR report gave the earlier Type 7/eCAR observations more causal weight than the Detection Engineer did. Cross-examination favored the narrower inference: a persistent LUID and session ID do not uniquely pair one earlier authentication with one later unlock, because a session can unlock repeatedly. A normalized observation of authentication is not independent proof of a later lock-state timestamp.

The Host/EDR reviewer explicitly revised the classification from `contract_gap` to `distribution_texture`. The two intervals remain one moderate recurring timing family. Earlier Type 7 records provide context, not proof that those particular lock pairs were displaced. Automation, cancelled transitions, or publication behavior remain plausible alternatives; the records do not prove that a human authenticated in under a millisecond.

### Weak observations challenged

Repeated Mac `cat` reads of binary documents are unusual for routine document viewing but compatible with inspection, scripting, adversarial activity, or selected collection. Reviewer overlap does not make the behavior impossible. Support-command fractional-second alignments likewise do not establish human entry or an impossible schedule. The TXT-query concentration could reflect a scheduled task. None became decisive or was promoted to a hard contradiction.

### Preserved exclusions

The panel did not score sparse Unified Log coverage, selected Sysmon event families, out-of-window process/session initiators, sanitized names, filesystem timestamps, or an easy-to-follow storyline as synthetic evidence. The unmatched SMB-mapping UID remained a collection-window limitation. Apparent TCP byte concerns were explained by the reported `missed_bytes` allowance; the CONNECT duration mode remained unproven as a defect. Neither a MeetingAssist policy message nor plist placement established successful denied execution, activation, or a child-effects contradiction.

## Round 3 — Actual Revised Positions

| Expert | Actual change | Influence reported in their own response |
|--------|---------------|------------------------------------------|
| Threat Hunter | Inconclusive → Synthetic; verdict confidence 85 → 94; synthetic-confidence 43 → 78 | Independent reproduction of the network DKIM finding was decisive. The collapsed lock cycles supplied secondary support; original Mac and fractional-second observations remained weak. |
| Detection Engineer | Inconclusive → Synthetic; verdict confidence 84 → 94; synthetic-confidence 38 → 78 | Independent DKIM decoding and trial division exposed a content issue outside the original structural checks. Host timing context modestly strengthened the existing concern without proving a unique authentication/unlock pairing. |
| Network Forensics | Synthetic unchanged; verdict confidence 96 → 97; synthetic-confidence 78 → 80 | The separate workstation timing family added modest support to the original DKIM finding. Strong transport/lifecycle evidence and possible content sanitization continued to limit the score. |
| Host/EDR Forensics | Synthetic unchanged; verdict confidence 80 → 96; synthetic-confidence 64 → 80 | Independent DKIM reproduction became the principal reason for the final verdict. The original lock interpretation was softened; the reviewer stated that endpoint evidence alone would now leave provenance inconclusive. |

The Host/EDR change is especially instructive: overall confidence increased while the strength assigned to the original endpoint claim decreased. The final verdict rests on newly tested content, not on preserving an overstated initial interpretation.

## Key Agreements

- **Advertised DKIM content is the strongest synthetic fingerprint.** All four final responses accept the repeated tiny-factor result; all distinguish syntactic validity from plausible cryptographic generation.
- **The two collapsed lock intervals are concrete, local timing concerns.** They are one recurring issue family, with plausible operational explanations and no established unique Type 7-to-4801 mapping.
- **Most checked structure remains convincing.** Process identity/hash continuity, visible lifecycle ordering, source-specific Windows shapes, Linux SSH semantics, macOS fork/exec transitions, and checked network/protocol relationships retain positive realism credit.
- **Technical coherence and constructed content can coexist.** Useful correlations neither prove production provenance nor become suspicious merely because they work.
- **Weak behavior and collection limits require restraint.** Mac document-command pairing, command phase alignment, and TXT scheduling receive limited weight; missing selected sources and slice boundaries are not defects by themselves.

## Key Disagreements

There is no final verdict split: every actual revised response says Synthetic. Remaining differences concern degree and inference:

- Final synthetic-confidence scores remain **78** for the Threat Hunter and Detection Engineer and **80** for Network and Host/EDR. The responses support that modest variation; they do not establish a shared numerical calibration or a negotiated aggregate.
- The original endpoint disagreement is preserved rather than erased. Host/EDR initially treated lock/authentication timing as a contract gap; Detection treated it as texture. Host/EDR explicitly softened that position after challenge. The panel now agrees on the observed intervals while leaving their cause unresolved.
- Alternative provenance explanations remain open. Broken published keys, deliberate test content, and key-content sanitization are possible. Reviewers found them insufficient to outweigh the repeated key pattern under the supplied briefing, but did not rule them out.

## Most Convincing Evidence

Ranked by the emphasis in the supplied reports and revised responses:

1. **Strong synthetic evidence — nine of twelve distinct DKIM RSA moduli have tiny prime divisors.** Reported witnesses include core DNS line 2239 (3, 17, 23), line 2386 (3, 383, 577, 929), and line 2481 (7, 29, 73, 521). Peer reproductions and consistent cross-sensor key bytes support the result. Repeated rows are not extra keys, and three keys passing this bounded small-factor test are not certified valid. This remains `distribution_texture`, not a mathematically impossible record or proof of a particular generator implementation.
2. **Moderate synthetic evidence — two native locked-state durations collapse below one millisecond.** WS-AJOHNSON records 318 microseconds and WS-MCHEN 955.7 microseconds, alongside ordinary minute-scale intervals elsewhere. This is corroborated timing texture, not demonstrated impossible authentication.
3. **Strong positive realism evidence — checked process identities and lifecycles remain coherent.** Independent endpoint checks found no demonstrated impossible ownership or visible lifetime contradiction under their respective tolerances and exclusions; macOS preserves fork versus exec distinctions.
4. **Strong positive realism evidence — transport/source semantics survive detailed pivots.** SSH/SMB staging, multipart proxy-leg distinctions, protocol/connection joins, TLS certificate visibility, and CONNECT/missed-byte accounting withstand the reported checks. These establish fidelity, not production origin.
5. **Weak synthetic evidence — seven Mac binary-document reads through `cat`.** Native and normalized observations corroborate the pairing, but workflow and collection alternatives substantially limit its authenticity value.

Support-command fractional phases and the TXT-query burst remain below these findings in weight.

## Most Debated Points

- **What valid syntax proves:** correct base64, ASN.1, bit length, and exponent did not establish realistic RSA key generation. This blind spot changed two verdicts and materially strengthened a third.
- **What sanitization permits:** changed names are allowed; changed cryptographic payloads are conceivable but were not established by the supplied evidence. This limits certainty and dataset-wide provenance claims.
- **What session equality proves:** a common long-lived LUID/session ID supports context but not a unique authentication/unlock join. This challenge caused an explicit reduction in the Host/EDR finding's classification.
- **How to weigh fidelity:** coherent sources and operational pivots are genuine strengths that constrain the scores; they do not negate a localized content fingerprint.
- **How to avoid double counting:** four DKIM confirmations are one cryptographic-content family; two hosts and multiple reviewers describe one lock-timing family; overlapping Mac observations are one weak behavioral family.

## Improvement Recommendations (Consensus)

The following priorities reflect all or most reviewers' stated recommendations; they do not assert an inspected implementation cause.

1. **Use genuine generated RSA public keys for advertised DKIM records.** Retain stable public material per selector/domain and across sensors. Validate reconstructed TXT content, decoded SPKI structure, modulus size, exponent, and genuine cryptographic key-generation provenance. Correct wrappers around arbitrary modulus-shaped bytes are insufficient. Do not expose private keys in telemetry. This is the highest-value recommendation and is supported by all four revised responses.
2. **Coordinate workstation lock-state and authentication timing according to the represented mechanism.** Investigate the two cited collapsed intervals. Preserve an actual human locked duration when human behavior is intended, or explicitly model a software-triggered transition when that is intended. Coordinate 4800, 4801, Type 7, and normalized observations before source rendering while preserving source-native timing differences. Do not move one row arbitrarily or assume a unique pairing solely from LUID equality. All four revised responses support this priority.
3. **Match document-access programs to intended workflows.** Where the intended activity is ordinary PDF/Office viewing, attribute access to the appropriate application/process behavior; preserve `cat` for explicit scripting or inspection. This is a lower-priority refinement supported by most reviewers, not a request to invent absent GUI coverage.
4. **Preserve the demonstrated fidelity during corrections.** Retain process GUID/hash integrity, visible lifecycle order, macOS fork/exec identities, source-specific Windows rendering, SSH/SMB transfer relationships, protocol timing, TLS 1.3 visibility limits, and CONNECT byte scopes. All four responses support preserving these strengths; adding arbitrary errors or unrelated missingness would not address the findings.

Lower-priority recommendations with narrower support remain distinct from the central consensus: tie background SPF/DMARC/DKIM/verification lookups to actual host roles and scheduled tasks, and derive support-command timing from its intended scripted or human execution mechanism. The reviewers did not establish either scheduling pattern as a hard defect or justify artificial jitter solely to hide regularity.
