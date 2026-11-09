# Deliberation Summary

This is a report-only facilitation of the four supplied independent assessments. No data, code, scenario, earlier assessment, or external source was inspected. The revised positions below are **facilitator-modeled responses to shared evidence, not actual new reviewer turns**. No reviewer was recontacted; agreement, revisions, and recommendations described here are provisional synthesis rather than new panel testimony. The reported observations have not been independently reverified by the facilitator.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 75 | 44 | Synthetic (facilitator-modeled) | 84 | 78 |
| Detection Engineer | Inconclusive | 78 | 32 | Synthetic (facilitator-modeled) | 83 | 74 |
| Network Forensics | Synthetic | 98 | 88 | Synthetic (facilitator-modeled) | 98 | 88 |
| Host/EDR Forensics | Synthetic | 87 | 71 | Synthetic (facilitator-modeled) | 90 | 80 |

Initial mean synthetic-confidence: **58.75/100**. Facilitator-modeled revised mean: **80.00/100**. These are unweighted descriptive means, not calibrated probabilities. The initial panel had two Inconclusive and two Synthetic verdicts. The modeled all-Synthetic outcome is an evidence-conditioned projection, not an observed unanimous vote.

## Round 1 — Present Findings

- **Threat Hunter:** Inconclusive, confidence 75, synthetic-confidence 44. Strong positive pivots include distinct local/network ownership for Windows `/netonly`, a successful proxy archive POST, and SSH/database-copy lifecycles that correlate across endpoints and sensors. Main negative observations are 37 of 2,261 DMZ HTTP records exactly 1 ms after connection start, repeated Mac shell vocabulary, and unusual `cat`/`tee` handling of office documents. The specialty-specific contribution is the practical investigation feasibility and restraint around policy warnings that do not establish execution.
- **Detection Engineer:** Inconclusive, confidence 78, synthetic-confidence 32. Windows process/session/handle relationships, source-specific schemas, parsing, and elementary network bounds generally pass. All 38 observed Security 4658 events contain an extra `ProcessName`; native-template fidelity is questionable, but collector enrichment remains plausible. The specialty-specific strength is distinguishing successful ingestion and elementary correlation from proof of packet-level fidelity.
- **Network Forensics:** Synthetic, confidence 98, synthetic-confidence 88. The principal claim is a completed, non-resumed TLS 1.2 RSA-2048 ECDHE_RSA exchange whose responder payload is certificate total plus only 280 bytes. The signature alone consumes 256 of those bytes, leaving too little for mandatory ServerHello and additional framing. The +280 residual repeats in 56 sensor-local certificate-bearing rows. A separate duration population contains 152 of 2,516 successful DMZ HTTPS flows within 1.200070–1.201719 seconds. Positive findings include coherent proxy legs, diverse DNS/state outcomes, stable certificates, and source-local tuple/UID integrity.
- **Host/EDR Forensics:** Synthetic, confidence 87, synthetic-confidence 71. Both Macs repeat exact fractional launch anchors and browser-helper offsets of +2/+3/+5 seconds; six inventory lifetimes are exactly two seconds. All 232 stat timestamps across 58 per-host executable-path observations have subsecond tails below 1,000 ns, although repeated metadata means these are not independent trials. One local shell also launches overlapping plain SSH clients and local commands, with unobserved job control a possible explanation. Strong positives are coherent Windows GUID lifecycles and careful Mac fork/exec/PID-version semantics.

## Round 2 — Cross-Examination

### Elementary byte checks versus full protocol accounting

The Detection Engineer's passing checks do not directly contradict the Network analyst's finding. Per-file size below directional payload, payload below IP bytes, and nonzero packet counts are necessary but insufficient tests. Two certificates can each fit separately while their combined size plus mandatory handshake bytes cannot fit. Network's core example, UID `ClI8KmgRGHYsTDasQq`, reports 3,348 responder bytes and two certificates totaling 3,068 bytes. Its stated cipher/key properties make the 280-byte residual the more specific test. Detection explicitly limits the elementary checks and does not claim packet-capture accuracy.

The strongest challenge to the network conclusion would concern the reported field semantics, certificate association/direction, cipher/key interpretation, completeness, or transformed counters. Network reports exact-UID responder association, complete files, zero missed bytes and a completed non-resumed exchange for the example. None of the other three reports supplies a contrary explanation. This strengthens the conditional synthetic conclusion without granting the facilitator independent verification or proving every network row defective. Sensor-local recurrence counts must not be presented as independent physical sessions.

### Coherent lifecycle versus templated timing

Threat and Detection found no checked impossible process lifecycle; Host agrees with those positives. Host's negative evidence concerns within-lifecycle scheduling and metadata distributions, which those identity/order checks do not test. A record can preserve correct process ancestry and still repeat implausibly precise helper offsets across two desktop launches. Successful correlation and suspicious distribution texture can coexist.

Scripts, application scheduling, inventory wrappers and export transformations are plausible alternatives. Exact repeated offsets alone do not prove synthesis. Repetition across command batches, browser helpers, inventory lifetimes and stat precision makes the combined concern stronger than any one instance, while leaving the alternatives unresolved. These patterns are not treated as independent probability multipliers.

### Narrow timing populations versus ordinary operational regularity

Threat's 37 exact 1 ms proxy HTTP offsets and Network's near-1.2-second TLS durations are distinct observations, not interchangeable measurements or proof of one shared cause. A proxy timestamp convention could explain the former; a timeout or configured behavior might explain duration spikes. Network's successful non-resumed exchanges, varied volumes and inbound/outbound paths weaken a simple failed-timeout explanation. The reports do not establish that every configuration-based explanation has been eliminated. Both remain distribution evidence, subordinate to the claimed byte-budget contradiction.

### Shell concurrency, office documents and enriched schemas

Host's same-shell SSH overlap does not conflict with Threat's observation that SSH clients remain alive through authentication and use. One tests foreground-shell availability; the other tests client lifetime and transport correlation. Unlogged suspension/backgrounding remains possible, so the overlap stays a bounded contract concern. Repeated `cat`/`tee` office-document activity and small command pools are behavioral concerns with scripted-use/shared-user explanations. Detection's extra 4658 field remains a limited native-schema concern with an enrichment explanation. None is promoted to an impossibility by combining reports.

## Round 3 — Revised Positions

**All revisions in this section are facilitator-modeled responses to shared evidence, not actual new reviewer turns.** Numerical changes are judgment-based projections; the reports contain no rule that uniquely determines revised scores.

- **Threat Hunter: 44 → 78; Inconclusive → Synthetic; verdict confidence 75 → 84.** The reported TLS lower-bound failure supplies the specific contradiction absent from this hunter's own checks. Host's cross-host timing and metadata observations add stronger distribution evidence than command repetition alone. The moderate revision retains the hunter's positive investigation pivots and uncertainty about collection/export conventions.
- **Detection Engineer: 32 → 74; Inconclusive → Synthetic; verdict confidence 78 → 83.** Network's aggregate certificate-plus-handshake accounting closes a blind spot explicitly outside elementary checks. Host's repeated timing patterns further limit what successful parsing and lifecycle checks establish. This modeled position retains the greatest residual caution because schema enrichment and transformed exports can be production-origin artifacts, and the specialist arithmetic has not been independently reproduced in a new turn.
- **Network Forensics: 88 → 88; Synthetic unchanged; verdict confidence 98 unchanged.** The other reports reinforce that strong coherence is real positive evidence but offer no rebuttal to the protocol lower bound. Host adds a distinct concern, yet it does not justify inflating an already strong score or treating every observed imperfection as independent confirmation.
- **Host/EDR Forensics: 71 → 80; Synthetic unchanged; verdict confidence 87 → 90.** Network's reported contradiction adds stronger evidence outside the host review. Threat and Detection's matching lifecycle positives support keeping the host claims narrowly scoped; unobserved job control and metadata/export transformation remain possible explanations for parts of the host finding.

## Key Agreements

The independent reports already support substantial agreement on the following observations; this is not a claim of new endorsement:

- Visible Windows process identities and checked lifecycle order are coherent. Threat, Detection and Host report compatible direct checks; none alleges a dataset-wide impossible process lifecycle.
- Cross-source pivots are usable and source semantics are often handled carefully. Strong UID/tuple matching, certificate identity, proxy routing and SSH/account ownership remain positive evidence rather than synthetic tells.
- Mac fork versus exec distinctions and policy-warning interpretation deserve preservation. Sparse selected-source coverage and absence of unrequired companion events are not themselves defects.
- The principal negative findings are localized. A TLS accounting contradiction, if the specialist report is accurate, can establish an authenticity problem despite otherwise useful telemetry; it does not invalidate every source family or event.

## Key Disagreements

- **Initial origin assessment:** Threat and Detection were Inconclusive; Network and Host judged Synthetic. The difference largely reflects review depth and tests, rather than directly conflicting raw observations. Only Network evaluated the decisive aggregate TLS budget; Host concentrated on precision distributions not covered by the other endpoint checks.
- **Weight of distribution texture:** Host assigns high weight to repeated Mac anchors and tiny stat tails. Threat assigns modest weight to repeated shell vocabulary and HTTP timing. These are different findings with different alternatives; no actual reviewer response establishes how much weight each would assign to the other's evidence.
- **Transformation versus generation:** Extra 4658 fields and narrow metadata precision could reflect exporters or sanitization. No report establishes such a transformation. The network report describes a tighter contradiction under the stated byte-counter and TLS semantics; the other reports neither refute nor independently verify it.

## Most Convincing Evidence

The following ranking synthesizes the strength and specificity claimed in the reports; it is not a newly recorded collective judgment.

1. **Reported TLS handshake byte deficit:** Core UID `ClI8KmgRGHYsTDasQq` leaves only 280 responder bytes after 3,068 certificate bytes; the stated RSA signature consumes 256 bytes before mandatory remaining messages. Complete-file/zero-missed-byte conditions and repeated +280 residuals make this the strongest evidence, conditional on the reported semantics and associations.
2. **Repeated Mac launch/lifetime templates:** Exact cross-host Chrome offsets, batch fractional anchors and six exactly two-second inventory lifetimes suggest schedule construction. They remain distribution evidence with operational alternatives.
3. **Mac stat precision distribution:** All 232 reported timestamps fall within the first microsecond of a second across unrelated executables and timestamp kinds. Repeated metadata and potential export transformations limit independence and certainty.
4. **Narrow TLS duration population:** 152 successful DMZ HTTPS flows occupy a 1.649-ms band near 1.2 seconds across multiple paths and widely varying byte volumes. This is more specific than a general claim that traffic looks regular.
5. **Coherent identities and operational pivots, favoring plausibility:** Multiple reports' lifecycle checks, realistic credential ownership, SSH evidence and actual proxy success materially constrain the conclusion. They show that the suspicious fingerprints occur within otherwise convincing telemetry.

Threat's exact 1 ms HTTP subset remains a useful secondary timing lead. The 4658 addition, mobile User-Agent context, shell concurrency and command vocabulary retain limited or conditional weight.

## Most Debated Points

- Whether successful elementary validation can rebut the TLS budget claim: it cannot test the missing aggregate condition, but the facilitator cannot substitute report comparison for fresh verification.
- Whether timing spikes imply synthetic origin: their precision, scope and recurrence matter, yet scripts, wrappers, timeouts or exporter conventions remain unexcluded alternatives.
- Whether a realistic attack investigation and strong process lifecycle imply authentic production origin: these demonstrate coherence and utility, while leaving protocol accounting and workload texture open.
- Whether overlapping SSH clients prove an impossible shell: they do not without excluding suspension, backgrounding or omitted job-control evidence.
- Whether schema additions and tiny timestamp tails identify synthesis or transformation: the reports support concerns, not a verified provenance explanation.

## Improvement Recommendations (Consensus)

No new consensus was obtained. These are prioritized report-supported recommendations and areas of compatible support, rather than unanimous endorsements. Apply repairs conditionally after reproducing the reported findings; retain correct relationships throughout.

1. **Repair TLS byte ownership and accounting first.** Network's specific recommendation is to budget the complete responder protocol exchange before finalizing connection counters: both DER certificates, certificate framing, ServerHello, signed ECDHE parameters, TLS records, Finished/tickets and STARTTLS dialogue where applicable. Detection's limits identify why elementary per-file checks would miss this. Preserve source-local certificate identities, tuples, observation differences and meaningful connection-state variation.
2. **Replace shared timing boundaries with activity-owned timing.** Investigate the successful TLS duration band and exact 1 ms proxy-HTTP subset separately. Derive transport/request/handshake timing from their appropriate lifecycle instead of fixed floors or unrelated post-render jitter. Network and Threat independently identify these respective populations.
3. **Make Mac scheduling reflect the visible workflow.** Follow Host's recommendation to vary plausible launch timing and browser-helper lifecycle behavior; separate inventory subprocess runtime from job schedule. For concurrent shell work, model distinct shells or explicit background/job-control behavior, or serialize foreground commands. Threat's command-pool observations support improving broader workflow texture without removing legitimate shared-user repetition.
4. **Use coherent filesystem metadata precision and installation history.** Host recommends retaining legitimate whole-second package timestamps where appropriate and avoiding tiny arbitrary nanosecond tails across all stat kinds. If an exporter transforms times, make the transformation explicit instead of treating the resulting precision as native filesystem evidence.
5. **Keep source-native payloads and behavioral context explicit.** Detection recommends native 4658 fields without `ProcessName`, or documented enrichment distinguishable from the native payload. Threat recommends activity-appropriate office-document operations or visible script context for `cat`/`tee`; Network's mobile-emulation/forwarding suggestion is lower priority and conditional on intent.

Preserve the shared strengths: Windows identity/handle/session relationships, Mac fork/exec distinctions, proxy-leg separation, SSH process and session lifetimes, meaningful sensor discrepancies and cautious treatment of policy warnings. No report supports adding arbitrary missingness, unrelated sources or noise solely to make successful checks less clean.
