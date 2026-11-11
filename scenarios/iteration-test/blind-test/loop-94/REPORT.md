# Loop 94 — Authenticity assessment

Implemented message-owned deferred mail provenance and regenerated the full fixed-seed scenario. Fresh raw logs are byte-identical to loop91; truth metadata now excludes unrelated background messages. Four fresh blind reviews completed.

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive; verdict confidence 76; synthetic-confidence score 20. The bounded sample is production-like: an SSH file transfer and an explicit-proxy upload can both be followed through endpoint and network records with consistent identities, tuples, timing, and byte direction. I found no demonstrated authenticity defect in the sampled records; that supports a low synthetic-confidence score, but twenty records and two pivots cannot distinguish actual production telemetry from a capable generator.

- **Detection Engineer:** Real; verdict confidence 65; synthetic-confidence score 20. The inspected records look production-like to a detection parser: Windows event-specific fields, numeric representations, identities, and source timestamp conventions are credible, and two exact cross-source pivots preserve their underlying facts. I found no substantiated synthetic indicator in this bounded review; the verdict remains tentative because a capable synthetic dataset could satisfy these same contracts.

- **Network Forensics Analyst:** Inconclusive; verdict confidence 78; synthetic-confidence score 30. The examined network evidence is mostly production-like, with plausible connection states, varied DNS outcomes, proxy traffic, and coherent exact protocol pivots. No demonstrated hard contradiction emerged from 20 individually examined records; the main reservation is a small, concentrated legacy TLS population, which is readily explainable by service policy and cannot establish origin.

- **Host/EDR Forensics Analyst:** Real; verdict confidence 60; synthetic-confidence score 25. The bounded endpoint sample is predominantly production-like: Windows process identity agrees across three sources, and a macOS SSH session has coherent network-before-authentication ordering and a stable session identity. I found no demonstrated impossible lifecycle, source-native field contradiction, or defensible distribution defect in this sample; the real verdict is tentative because structurally competent synthetic telemetry could also pass these checks.

## Deliberation Findings

Triggered by two Real/two Inconclusive verdicts. Facilitator preserved original mean23.75; no new concrete raw-log correction supported.

## Prioritized Improvements

- **Fixed P1 — Independent background mail borrowed authored intent.** Canonical probe, eight messages/four actions→zero, high provenance leverage. Exact message identity now owns late hops; explicit intent remains authoritative; independent background mail cannot borrow shared process/action ownership.
- **P1 — Remaining source-contract agreement.** Automated hard gate88.1343<95. Native ICMP port slots are a confirmed next verifier mismatch:507 present rows require type8 but capture expects canonical0. Owner: source-native evidence rules; medium-to-high correctness leverage, low-to-medium schema risk.
- **P3 — Small DB TLS/cipher concentration.** Network (original rating:not labeled), small service-specific population, low leverage. Policy explanation remains plausible and no fix selected.

## Priority Rationale

Canonical provenance was repaired at the journal owner, preserving raw telemetry. The next target is a demonstrated native representation error rather than the blind panel's weak population texture.

## Family Contract and Verification

family_level. GroundTruthLedger stores email:<message_id> in its existing disk-backed ownership table. No-lineage/background mail resolves only through an already-owned exact message; explicit intent wins. Non-mail process inheritance stays intact.22 journal tests cover shared/new action, unrelated process borrowing, late same-message hop, explicit override and checkpoint-restore variants.29 independent source-agreement tests and existing source/identity controls pass. mail-attribution-probe shows0 mismatches (previous8); raw callback remains non-TLS. data-equivalence.json confirms all118 source files byte-identical. Behavior508 records the metadata-only ownership correction. Broader non-mail attribution remains separate.

## Comparison with Quantitative Eval

Automated evaluation: **94.4923/100 FAIL**, 147,759 records. 94.4923 FAIL,147,759 records; ground-truth88.1343. Authored email outcome mismatches are eliminated. Remaining native requirements, source capability/filter decisions and missing-evidence checks remain active; no thresholds lowered.

## Score Movement and Next Loop

Mean23.75 versus24.25 in loop93 (-0.50) on byte-identical raw data; reviewer variance. Deliberation kept both Real and Inconclusive positions and all original scores. Loop95 will align ICMP native projection with its required-fact contract.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.
