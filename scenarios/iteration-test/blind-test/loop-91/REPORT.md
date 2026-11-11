# Loop 91 — Authenticity assessment

Repaired typed pipeline protocol intent and exact RDP reconnect admission for unmodeled controllers; generated a fresh successful seed42 bundle and ran four independent reviews. Preserved the failed initial candidate separately.

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 30. The inspected evidence is mostly production-like, with technically coherent SSH and process-identity pivots and a plausible mixture of routine endpoint and network activity. A bounded review of 18 representative records and aggregate summaries found no demonstrated impossible ordering, invalid identity relationship, or required-companion gap; the principal weak suspicion is a uniform fleet-wide sysstat command pattern, which also has a straightforward operational explanation.

- **Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 30. The inspected records look substantially production-like and should support ordinary SIEM parsing and identity-based pivots. I found no demonstrated source-native contradiction in the representative sample or the two exact pivots; the limited, deliberately bounded inspection cannot establish whether well-correlated telemetry came from production or a capable simulator.

- **Network Forensics Analyst:** Real; verdict confidence 63; synthetic-confidence score 24. The examined network evidence is mostly production-like: transport accounting, DNS response diversity, proxy semantics, certificate references, and protocol timing agree in the checked examples. I found no demonstrated impossible ordering, malformed native protocol value, or broken exact-identity join; the modest synthetic-confidence score reflects a narrow TLS distribution on the database observation path rather than a decisive defect. This is a bounded authenticity assessment, not proof of origin.

- **Host/EDR Forensics Analyst:** Inconclusive; verdict confidence 80; synthetic-confidence score 25. The sampled endpoint evidence is mostly production-like: Windows process identities, Linux SSH sessions, and macOS fork/exec distinctions survive exact-identity checks without a demonstrated impossible relationship. The only retained synthetic hint is repeated presentation metadata in the very small macOS Unified Log sample; its significance is weak and does not establish a native schema error or justify a synthetic verdict.

## Deliberation Findings

Triggered by Real/Inconclusive disagreement. Facilitator preserved original scores and reported mean27.25, with no demonstrated new unconditional correction.

## Prioritized Improvements

- **Fixed P0 — Raw Bash socket falsely negotiated TLS.** Threat Hunter loop89 (original rating:not labeled), one exact callback, high leverage. Parent submission now supplies protocol semantics while final child retains socket/process identity; rendered probe changes1 contradiction→0.
- **Fixed P1 — Unmodeled RDP controller could not reconnect.** Generation guardrail, exact disconnected session, high execution leverage. Shared admission now delegates to the already-supported exact reconnect bundle; unavailable modeled controllers remain rejected.
- **Open P1 — Ground-truth acceptance.** Automated check, multiple source/attribution contracts, high leverage. Ground-truth88.0920 remains below95; no pass claimed.
- **P3 — Repeated commands/shared Unified Log metadata and narrow DB cipher population.** Threat/Host/Network (not labeled), weak distribution/source-semantics cues, low leverage and uncertain corrective value. Preserve source-native callsite/build metadata until a contradiction is established.

## Priority Rationale

Both changes correct semantic owners, without rewriting source rows or tuning the scenario. New weak concerns do not justify arbitrary jitter or metadata mutation. Acceptance remains independent of production-like blind scores.

## Family Contract and Verification

adapter_to_family_model for pipeline: exact concurrency-group/parent relation recovers the original submission and reuses the existing decoder and canonical network planner. Tests cover raw/encoded pipelines,443/8443 and unrelated-parent refusal;37 focused tests pass. family_level RDP admission: initial/exact reconnect paths now agree about unmodeled source support;45 routine plus1 slow test pass. Fresh data show original source10.10.1.99, unchanged LUID0x26db2b9 and sessionRDP-Tcp#3 across4779→4778, with no fabricated source host. Raw probe retains one callback and zero SSL/certificate companions. Behavior revisions506–507 registered;102 config files valid; Ruff/format/diff checks pass. Residual source attribution and schema-v5 contract failures remain separate.

## Comparison with Quantitative Eval

Automated evaluation: **94.4818/100 FAIL**, 147,759 records. Overall94.4818 FAIL, ground-truth88.0920; all other pillars exceed90. Record count147,759 versus148,961 before correction reflects real downstream deterministic activity changes, so this is not a single-row-only comparison.

## Score Movement and Next Loop

Mean27.25 versus26.75 in loop90 (+0.50). The hard rendered invariant improved, while this small blind movement is consistent with reviewer variance; do not infer a realism regression. Loop92 verifies requested-vs-expanded email recipient semantics on unchanged source data.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.
