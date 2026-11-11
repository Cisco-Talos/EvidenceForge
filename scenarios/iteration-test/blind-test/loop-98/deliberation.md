# Deliberation Summary

This is a bounded facilitator synthesis of the four submitted reports only. No additional records were opened and no experts were reconvened. Cross-examination below compares existing evidence; it does not attribute new statements, agreement, revisions, or votes to the experts.

## Panel Composition

| Expert | Original verdict | Verdict confidence | Synthetic-confidence | Revised position |
|---|---|---:|---:|---|
| Threat Hunter | Real | 60 | 25 | Not solicited; original retained |
| Detection Engineer | Inconclusive | 80 | 20 | Not solicited; original retained |
| Network Forensics | Real | 58 | 18 | Not solicited; original retained |
| Host/EDR Forensics | Inconclusive | 80 | 20 | Not solicited; original retained |

Original synthetic-confidence mean: **20.75/100** = (25 + 20 + 18 + 20) / 4. Verdict confidence is separate and was not used as a weight.

Original realism scores are preserved below, in the reports' category order; these are separate from synthetic-confidence.

| Expert | Field format | Temporal | Correlation | Behavioral | Environmental |
|---|---:|---:|---:|---:|---:|
| Threat Hunter | 8 | 8 | 9 | 8 | 8 |
| Detection Engineer | 9 | 8 | 9 | 8 | 8 |
| Network Forensics | 9 | 9 | 9 | 8 | 8 |
| Host/EDR Forensics | 9 | 9 | 9 | 9 | 8 |

## Round 1 — Findings Presented

- **Threat Hunter:** Real, confidence 60, synthetic-confidence 25. The exact encoded PowerShell command, PID, parent, principal and logon ID agree between eCAR and Sysmon. A later SCP process has a matching outbound tuple and two sensor observations, followed by receiver SSH acceptance within the transport interval. The apparent sysstat repetition resolves to 36 executions per Linux host at about ten-minute intervals, compatible with a managed timer rather than evidence of templating. Nineteen representative records were inspected.
- **Detection Engineer:** Inconclusive, confidence 80, synthetic-confidence 20. Windows Security/Sysmon source fields and hexadecimal/decimal identifiers are plausible; the taskhostw pivot agrees with eCAR within roughly 142 ms. Exact early and late TLS joins preserve tuple and handshake timing. The expert distinguishes service logons, unrelated sampled sessions, macOS sources, and collection boundaries rather than making absence-based allegations. Twenty-two records were inspected.
- **Network Forensics:** Real, confidence 58, synthetic-confidence 18. The middle TLS/connection/certificate pivot preserves identity and timing; late DNS resolution precedes the proxy connection and TLS handshake. The accounting screen's 179 flags all coincide with positive missed bytes and gap-bearing history. The DB segment's 19 TLS rows are exclusively TLS 1.2, including 11 CBC rows, but this receives negligible authenticity weight. Twenty records were inspected.
- **Host/EDR Forensics:** Inconclusive, confidence 80, synthetic-confidence 20. Two Windows process pivots preserve identities and parent/credential facts. macOS fork, xpcproxy exec and Chrome exec retain one process lifetime with advancing pidversions; normalized CREATE/MODIFY keeps the same object. SSH connection, acceptance and PAM opening remain ordered for one tuple and sshd PID. Seventeen records were inspected.

## Round 2 — Cross-Examination

### Real versus Inconclusive is a provenance limit

The 2 Real / 2 Inconclusive split does not reflect opposing technical findings. All four reports describe production-like inspected records and no demonstrated score-bearing contradiction. The Real assessments are explicitly modest appearance-based leanings. The Inconclusive assessments reserve provenance judgment because accurate schemas and coherent joins can also be produced by sophisticated synthesis. Their confidence of 80 concerns the inconclusive classification, not an 80% probability of real provenance. The low synthetic-confidence scores and inconclusive verdicts are therefore compatible. The reports do not establish ground truth or dataset-wide indistinguishability.

### Capture-gap accounting resolution

The network report records 93 core, one DB and 85 DMZ TCP rows triggering a naive minimum-header screen: 179 total. Every flagged row also has positive `missed_bytes` and gap-bearing history; no flag has IP-byte totals below its sequence-derived payload total. Sequence-derived payload and captured packet/header totals need not describe identical observed bytes when capture gaps exist. On this evidence the naive screen is insufficient to establish impossible accounting. The other reports identify no contrary packet-accounting evidence. This resolves the candidate allegation for this bounded review; without packet evidence it does not certify every gap or accounting field across the collection.

### Weak DB TLS profile

The comparatively narrow DB TLS profile (19/19 TLS 1.2; 11/19 CBC) differs from the DMZ's TLS 1.3 majority. It can fit a legacy service segment, and a small segment-specific population should not be forced to resemble Internet-facing traffic. No deployment inventory or server capability evidence establishes that those negotiations are impossible. The network expert labels it a weak signal with negligible authenticity weight; the synthesis preserves that qualification. Neither upgrading ciphers nor adding version diversity is a supported realism correction from these reports.

### Strength challenges and limits

Exact process joins, distinct source identifiers and realistic observation offsets support local consistency, not provenance. The SCP pivot establishes process/transport/authentication feasibility, not inspected file receipt, integrity or shutdown. The macOS evidence supports fork-versus-exec semantics, while full version-specific serialization remains unverified. Ordinary timer regularity is compatible with scheduled collection; more irregularity would not automatically be more realistic. Missing sampled initiators, unequal create/terminate aggregates, absent source types and six-hour boundaries cannot establish lifecycle defects without exact in-window evidence.

## Round 3 — Positions Retained

No revisions or re-votes occurred. All original verdicts, confidences, synthetic-confidence scores and category scores remain as submitted. The cross-examination supplies a facilitator explanation of their compatibility, not a newly achieved consensus or a fifth authenticity verdict.

## Round 4 — Assessment of Agreements and Differences

### Agreements supported by the reports

All four reports find no demonstrated corrective defect in their bounded samples. Most directly support coherent shared process or network facts while preserving source-specific identities, timestamp precision and observation delays. None supports penalties for suspicious narrative content, sanitized domains, source completeness, unexamined companion evidence, or initiators potentially outside the capture window.

### Remaining disagreement

The classification threshold remains different: two experts lean Real from plausible appearance; two retain Inconclusive because appearance cannot identify origin. Reported confidence and scores must remain attached to those original judgments. No technical disagreement requires selecting a stronger side on provenance.

### Most convincing reported observations

The following is a facilitator ordering of concrete evidence strength, not a panel ranking or new vote:

1. Exact multi-field Windows process pivots across native and normalized sources, including command, PID/parent, principal and session identity.
2. Exact TLS UID/tuple/certificate joins and connection-before-handshake timing; contextual DNS remains a distinct transaction.
3. macOS fork/exec continuity with stable process identity and changing images/pidversions.
4. SSH transport-before-authentication/PAM ordering and the separate SCP tuple corroboration.
5. Aggregate capture-gap accounting explains the naive screen flags; it removes a proposed contradiction rather than proving origin.

### Concrete correction assessment

**No supported concrete generation correction emerges from the four reports.** This is the reports' common recommendation, not an assertion that every record is correct. Preserve the demonstrated source-local identities, platform semantics, observation offsets, SSH ordering and capture-gap behavior. An inventory comparison for DB TLS or separately authorized packet/native-schema/lifecycle review could resolve remaining uncertainty; those are validation steps, not current defects or required content additions. Do not change TLS negotiation, inject arbitrary retries/noise, invent missing companions, or impose narrative/completeness penalties on the basis of these findings.
