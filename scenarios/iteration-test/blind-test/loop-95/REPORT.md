# Loop 95 — Authenticity assessment

Aligned Zeek-native ICMP state/type/code projection and immutable required-fact construction, then regenerated source expectations and ran four independent reviews. All118 source files remain byte-identical to loop94.

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive; verdict confidence 75; synthetic-confidence score 20. The bounded sample is production-like: two exact cross-source pivots preserve account, endpoint, transport, application, and timing relationships without a demonstrated contradiction. I cannot determine origin from this sample; the low synthetic-confidence score describes the observed telemetry, while the verdict confidence describes confidence that the available evidence does not support an origin determination.

- **Detection Engineer:** Inconclusive; verdict confidence 78; synthetic-confidence score 20. The bounded sample is production-like from a detection-pipeline perspective: XML and JSON records parse, the examined Windows event fields are internally sensible, and exact endpoint and network joins preserve identity and plausible timing. I found no demonstrated authenticity defect in the reviewed records; that supports a low observed synthetic-confidence score but does not establish production origin, so the origin verdict remains inconclusive.

- **Network Forensics Analyst:** Real; verdict confidence 64; synthetic-confidence score 24. The sampled network telemetry is mostly production-like: protocol records agree with their exact connection identities, failed TCP attempts retain appropriately sparse evidence, and the DNS and TLS populations contain credible variation. I found no demonstrated impossible ordering, impossible packet accounting, or required missing companion in this bounded review; the real verdict is tentative because a well-modeled synthetic collection could reproduce these properties.

- **Host/EDR Forensics Analyst:** Inconclusive; verdict confidence 82; synthetic-confidence score 35. The examined endpoint evidence is mostly realistic: exact Windows process identities and a Linux SSH session agree across independent source families, and macOS records distinguish fork from successive executable images. I found no demonstrated impossible lifecycle, denied-execution effect, or native-field contradiction in this bounded review; repeated Windows service command vocabulary is a weak indication of templating, with ordinary administrative activity an equally viable explanation.

## Deliberation Findings

Triggered by Real/Inconclusive verdict disagreement. Facilitator preserved all original scores and mean24.75; workload/stack-conditioned texture checks remain suggestions, not new defects.

## Prioritized Improvements

- **Fixed P1 — ICMP canonical port0 falsely required as native type.** Automated source probe,507 present expectations, high correctness leverage. Source-native rules now share type/code and OTH-state projection with the serializer;507 field disagreements→zero.
- **P1 — Remaining schema-v5 acceptance.** Automated hard gate, repeated source-family findings, high leverage. Ground-truth88.3573 remains below95; missing/duplicate evidence, source admission and timing proof identities require independent qualification.
- **P2 — Linux PID floor.** Detection loop89 (original rating:not labeled), ten hosts, medium realism leverage and high allocator risk. A dedicated follow-up probe is next; no output-only jitter.
- **P3 — Service command/TCP-history texture.** Host/Network (not labeled), weak, low leverage. Path escaping suspicion was independently cleared after parsing; no schema correction supported.

## Priority Rationale

Fixing an exact native representation error improves verifier correctness without altering already-correct packets. A small automated score increase does not establish a blind realism improvement.

## Family Contract and Verification

source_native_single_schema. Pure conn state/history helpers moved from Zeek emitter support into evidence_source_rules; both serialization and native_requirements consume the same semantic port/state projection. Central controls cover zero/default and explicit ICMP types, answered/unanswered, direct/sensor paths and negative altered type/state; TCP/UDP output preserved.50 focused ICMP/repair tests and45 Zeek format/projection tests pass. Final combined related suite:255 passed,9 deselected; targeted RDP slow test1 passed. Behavior509 and102 config files validate; Ruff and formatting pass. Sources: https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html documents native ICMP tuple semantics. icmp-contract-probe.json checks507 rows, zero missing or disagreeing; data-equivalence.json proves unchanged raw data.

## Comparison with Quantitative Eval

Automated evaluation: **94.6124/100 FAIL**, 147,759 records. 94.6124 FAIL, ground-truth88.3573,147,759 records. factual_disagreement832→325 exactly matches507 corrected ICMP checks. No acceptance threshold or comparison tolerance changed.

## Score Movement and Next Loop

Mean24.75 versus23.75 in loop94 (+1.00) on byte-identical raw data; reviewer variance. Deliberation retained original positions and cleared the path-escaping suspicion. Loop96 qualifies allocator texture on the same fixed snapshot.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.
