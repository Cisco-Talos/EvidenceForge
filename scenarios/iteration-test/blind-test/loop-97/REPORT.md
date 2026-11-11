# Loop 97 — Authenticity assessment

Inventoried the unresolved schema-v5 acceptance families against exact-source ownership boundaries and ran another independent blind panel on the unchanged loop95 snapshot. No code or scenario change.

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive; verdict confidence 82; synthetic-confidence score 35. The bounded sample looks mostly operationally plausible, with usable process, account, network and proxy pivots and substantial background telemetry. I found no demonstrated impossible lifecycle or ordering relationship; the strongest concern is weak repetition in two Mac process populations, which could also reflect collection scope and does not establish synthetic origin.

- **Detection Engineer:** Inconclusive; verdict confidence 85; synthetic-confidence score 20. The bounded sample looks suitable for ingestion and identity-based detection: Windows XML fields, Zeek typed JSON, and endpoint process identities are internally coherent in the records inspected. I found no demonstrated source-native contradiction or impossible visible ordering; that supports a low synthetic-appearance score but does not establish production provenance.

- **Network Forensics Analyst:** Inconclusive; verdict confidence 80; synthetic-confidence score 28. The bounded network sample is mostly production-like: transport and protocol records agree on exact identities, TLS observation respects encrypted certificate visibility, and DNS and connection outcomes show meaningful variety. I found no demonstrated source-native contradiction; the limited six-hour window and 19 inspected records do not establish whether the collection is real or synthetic.

- **Host/EDR Forensics Analyst:** Inconclusive; verdict confidence 78; synthetic-confidence score 32. The bounded endpoint sample is mostly production-like: Windows process identities agree across three sources, Linux SSH authentication agrees with normalized session telemetry, and macOS records distinguish fork and successive exec images. Repetitive macOS version-query activity is a weak texture signal, but I found no demonstrated impossible identity, ordering, or field value in the inspected records; this sample cannot reliably establish origin.

## Prioritized Improvements

- **P1 — Remaining ground-truth native/source-observation contracts.** Automated, full-dataset2831 incorrect checks across multiple source families, high correctness leverage. agreement88.3573<95 persists; missing/duplicate evidence and native facts need exact row qualification, not broad exemptions.
- **P2 — Linux PID capacity floor.** Detection loop89 (original rating:not labeled), ten hosts/67 exact+940 intervals in350, medium leverage/high allocator risk; retain the dedicated roadmap contract.
- **P3 — Mac shell/inventory frequency.** Threat/Host (not labeled), weak behavioral texture, low leverage. Complete supported process-start coverage and explicit inventory commands can explain the population; no unsupported helper or source expansion selected.

## Priority Rationale

Independent raw-log plausibility does not close the separate canonical metadata/evidence gate. Prioritize a source-owner investigation with reproducible identities ahead of low-confidence vocabulary or host-profile tuning.

## Family Contract and Verification

new_family inventory/no fix claimed. acceptance-failure-inventory.json retains complete rule counts, bounded sampled formats and owner inventory: expectation capture, source-native requirements, exact-source admission/observation, timing receipts and authored reconciliation.17,398 correct/2,831 incorrect checks and4,854 diagnostic findings are distinct quantities;4,467 coverage gaps remain separately classified. Future fixes must establish each required row's identity and native view, preserving valid source loss/windows/filtering and negative controls. No source family, predicate, tolerance or threshold disabled.

## Comparison with Quantitative Eval

Automated evaluation: **94.6124/100 FAIL**, 147,759 records. 94.6124 FAIL,147,759 records; unchanged source bytes and current evaluator. Ground-truth88.3573 remains the only failed hard acceptance criterion.

## Score Movement and Next Loop

Mean28.75 versus25.50 in loop96 (+3.25), unchanged data: reviewer variance and weak Mac population emphasis. All four verdicts Inconclusive, confidence78–85, spread15; no deliberation trigger. Loop98 is the final requested independent checkpoint with early/middle/late sampling and final dashboard.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.
