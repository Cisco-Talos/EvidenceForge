# New assessment epoch — loop 1

Fresh baseline on the approved expanded canonical scenario. No prior canonical
or exploratory-candidate score is inherited. Scenario and reviewer instructions
are unchanged; no engine fix is claimed for this measurement.

## Scores

Automated evaluation **PASS 98.5274**, 149,690 records. Parseability 100,
plausibility 96.8145, causality 99.7589, timing 99.0457, ground truth 97.0180.
No acceptance/parse failure or automated-score investigation trigger.

| Expert | Initial verdict | Verdict confidence | Synthetic-confidence score | Actual deliberation score |
|---|---|---:|---:|---:|
| Threat Hunter | Inconclusive | 85 | 43 | 78 |
| Detection Engineer | Inconclusive | 84 | 38 | 78 |
| Network Forensics | Synthetic | 96 | 78 | 80 |
| Host/EDR Forensics | Synthetic | 80 | 64 | 80 |
| Mean | | | **55.75 — mixed/inconclusive** | **79 — likely synthetic** |

Lower synthetic-confidence scores are better. The initial mean is the trend
measurement. The five-score rolling mean is 55.75 (n=1). This is a new baseline;
there is no prior-loop score movement to diagnose.

## Individual expert summaries

The threat hunter found usable process/session/transfer pivots and no demonstrated
lifecycle contradiction in bounded checks. Seven Mac binary-document reads via
cat were a modest behavioral concern; limited fractional-second command spacing
was weak evidence. Initial score 43, verdict confidence 85.

The detection engineer found credible native shapes and broad identity/transport
consistency. Two Windows lock/unlock intervals below one millisecond were a
localized distribution concern rather than an established impossibility. Initial
score 38, verdict confidence 84.

The network specialist found nine of twelve distinct DKIM public-key moduli had
trivially small prime factors despite valid DER, size and exponent. This was the
dominant authenticity finding; transport, protocol and certificate-reference
checks otherwise held. Initial score 78, verdict confidence 96.

The host specialist found the same collapsed Windows lock intervals, alongside
earlier Type 7/eCAR authentication observations. Mac process identities and
fork/exec semantics were convincing; repeated cat/document pairing was weak.
Initial score 64, verdict confidence 80.

## Deliberation

Verdict disagreement and a 40-point initial score spread triggered the existing
procedure. All four experts independently reproduced the DKIM factor witnesses
and actually revised or reaffirmed their positions: final scores 78/78/80/80,
all Synthetic. They qualified the lock issue as timing texture: a shared session
LUID does not uniquely join an earlier Type 7 event to one particular 4801.
The facilitator preserved these actual votes and caveats; original reports are
unchanged. Deliberation is excluded from trend averages.

## Prioritized improvements and classification

No P0 impossibility or native-schema contradiction was demonstrated. Original
reviewers supplied no P0–P4 labels; priorities below are synthesis ratings.

| Priority | Issue/category | Evidence and classification | Original rating | Score leverage / owner / risk |
|---|---|---|---|---|
| P1 | Invalid RSA public material; distribution_texture | Network, reproduced by all four in deliberation. Nine of twelve unique DKIM moduli have factors below 10,000. `new_family`. | not labeled | High; shared cryptographic material registry. Medium risk because RSA certificate identity is a sibling consumer. |
| P1 | Collapsed workstation lock intervals; distribution_texture | Detection and Host independently observed 318 µs and 955.7 µs native intervals on two hosts; normal minute-scale intervals also exist. `sibling_defect`, precise cause pending. | not labeled | Medium/high; auth/session lifecycle and source timing. Verify the owning timestamp/state relationship before changing it. |
| P2 | Repeated fresh machine TGT issuance; environment_or_collection_plausibility | Root rendered-output probe: 798 TGT audits, including 62–111 per ordinary Windows machine in six hours. Forced baseline and machine-logon AS paths bypass the reusable cache. `sibling_defect`; not attributed to a blind reviewer. | not labeled | Medium, uncertain direct score effect; shared Kerberos/DC cache with baseline adapters. Low/medium risk; preserve explicit ticket intent and audit/transport companions. |
| P3 | Repeated shell-to-SSH launch lead; distribution_texture | Root probe finds the same command/session repeating native lead near 4.334 s; code seed omits invocation identity. `sibling_defect`; not a blind score driver claimed here. | not labeled | Medium/low; shared Windows CLI parent timing, with SCP/SFTP siblings. Low risk once source-deadline checks are retained. |
| P3 | Raw binary-document reads via cat; weak_signal | Threat and Host observed seven Office/PDF reads on the second Mac. Possible scripted inspection and export selection remain explanations. `false_positive_or_unproven` as a generic document-consumption defect. | not labeled | Low; inspect intended baseline activity/process binding before inventing app evidence. |
| P4 | Localized background TXT queries; weak_signal | Network observed 34 of 35 queries in roughly 23 minutes across 19 clients. A coordinated diagnostic task is plausible. `false_positive_or_unproven`. | not labeled | Low; DNS/task scheduling and host-role binding, subject to further evidence. |
| P4 | Support-command fractional alignment; weak_signal | Threat observed two short sequences with similar fractional timestamps; scripting/scheduling remain plausible. `false_positive_or_unproven`. | not labeled | Low; execution/interaction timing, only if a concrete inconsistency emerges. |

## Next family pass and rationale

Target the shared RSA builder first, plus the verified implicit-machine TGT cache
bypass. The former changed every expert's deliberated assessment; the latter is
a high-frequency operational-model defect with a bounded shared-owner correction.
The lock timing issue remains a high priority but needs its root cause established
before a repair; do not patch one rendered 4800/4801 row. Contracts and sibling
inventories for the selected families are in loop 2.

The new RSA invariant is a modulus composed of independently scoped large primes,
with deterministic identity, correct bit length and exponent. The TGT invariant
is valid machine-ticket reuse for implicit requests, without suppressing explicit
AS requests or creating AS-only transports on cache hits. Neither requires a
scenario edit or new reviewer examination guidance.

## Quantitative evaluation versus expert evidence

The high automated score confirms existing guardrails, not production origin.
The panel uncovered mathematically implausible key content and unusual lock-state
timing that passed those guardrails. Both automated and expert checks found broad
process/transport coherence; complete matching is not an authenticity defect.
Unmatched SMB mapping, sparse selected Mac Unified Log coverage and narrative
completeness were explicitly excluded from the synthesized issue list.

## Provenance and artifacts

Generation behavior revision 534, seed 42. Validation passed with zero errors and
eight intentional warnings. `input-provenance.json` identifies authored hashes;
`blind-review-provenance.json` records verified neutral data-copy and unchanged
briefing/persona hashes. Original reports, actual reviewer deliberations,
facilitator summary, automated JSON/text, source-aware probes and the authoritative
bundle are retained in this loop directory. The RSA probe independently confirms
nine of twelve affected keys; absence of small factors alone will not count as
proof of correctness after repair—native key validation tests cover the builder.
