# Loop 93 — Authenticity assessment

Qualified the remaining mail provenance failure against canonical occurrence and artifact identities, then ran a fresh independent panel on unchanged loop91 data. No output change in this checkpoint.

## Individual Expert Summaries

- **Threat Hunter:** Real; verdict confidence 58; synthetic-confidence score 20. The bounded sample is production-plausible: two independently selected SSH sessions join by exact transport tuple across endpoint and network sources with transport-before-authentication ordering. I favor real data only slightly; I found no demonstrated contradiction, but nineteen inspected records and targeted aggregates cannot establish authenticity or exclude sophisticated synthetic generation.

- **Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 28. The bounded sample is mostly production-like from a detection ingestion and correlation perspective: Windows fields are internally coherent, two exact cross-source pivots preserve identities and causal ordering, and sampled Mac records distinguish the executing actor from the post-exec target. I found no demonstrated contradiction sufficient to distinguish a carefully constructed synthetic collection from real telemetry; the verdict confidence reflects confidence in that qualified conclusion, while the score of 28 describes the realistic appearance of this sample.

- **Network Forensics Analyst:** Inconclusive; verdict confidence 78; synthetic-confidence score 29. The inspected network evidence is mostly production-like: TCP outcomes, DNS failures and query diversity, TLS resumption and certificate reuse, and proxy byte accounting are internally plausible. Two exact pivots produced coherent transport/application relationships, and the bounded review did not demonstrate an impossible ordering or source-native contradiction; those results support a low synthetic-confidence score but cannot establish real provenance.

- **Host/EDR Forensics Analyst:** Inconclusive; verdict confidence 75; synthetic-confidence score 20. The inspected endpoint evidence is production-like: exact Windows process and network joins, a Linux SSH session, and a macOS fork/exec transition preserve sensible identities and ordering. This bounded review demonstrated no qualifying synthetic defect, but realistic endpoint contracts do not establish real-world provenance, so the authenticity verdict remains inconclusive.

## Deliberation Findings

Triggered by Real/Inconclusive verdict disagreement. Facilitator retained mean24.25 and found no new unconditional raw-log defect; suggested exact SSH close qualification rather than inferring missingness.

## Prioritized Improvements

- **P1 — Independent mail inherits an earlier authored action.** Automated/canonical probe, four actions/eight distinct messages, high provenance leverage. Auto-named .eml artifacts and different message IDs/recipients were attached through reused process/action ownership. Owner: GroundTruthLedger inheritance, medium risk requiring late-companion and checkpoint controls.
- **P1 — Ground-truth source-contract failures remain.** Automated families, repeated, high acceptance leverage. Preserve failed gate and independent native evidence verification.
- **P3 — SSH close qualification.** Facilitator follow-up, not a blind reviewer defect rating; explicit closure remains to be joined for selected sessions, with bounded-window qualifications. No impossible close identified.

## Priority Rationale

The code-aware provenance contradiction is separate from the blind panel: reviewers correctly judge raw logs without access to faulty ground-truth labels. A focused journal fix is preferred over weakening authored-mail verification.

## Family Contract and Verification

new_family diagnosis. mail-attribution-probe.json joins canonical message IDs to ARTIFACTS_MANIFEST entries and authored artifact/recipient intent, identifying eight separate messages across four actions. Next contract uses exact message ownership for late hops, while an independently declared background message cannot inherit from borrowed process/action identity alone. Existing SQLite ownership/checkpoint machinery remains the owner. No report filtering or scenario change.

## Comparison with Quantitative Eval

Automated evaluation: **94.4825/100 FAIL**, 147,759 records. Identical source data and current evaluator:94.4825 FAIL, ground-truth88.0955,147,759 records. Missing/factual/source-admission families remain independently counted.

## Score Movement and Next Loop

Standalone mean24.25 versus26.75 in loop92 (-2.50) on byte-identical data; sampling/reviewer variance. Deliberation preserved original scores. Loop94 will verify message-owned provenance with fresh generation and late-hop/checkpoint controls.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.
