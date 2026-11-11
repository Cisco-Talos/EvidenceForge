# Loop 89 — Authenticity assessment

Fresh current-dev generation, quantitative evaluation and four independent blind reviews completed. No generation fix in this baseline round; selected concrete evidence for the following repairs.

## Individual Expert Summaries

- **Threat Hunter:** Synthetic; verdict confidence 91; synthetic-confidence score 76. This is a substantial, usable six-hour enterprise collection with credible Windows, Linux, macOS, proxy, firewall and network pivots. My synthetic verdict rests principally on one demonstrated protocol contradiction: the exact connection owned by a visible Bash `/dev/tcp` reverse shell is also reported as a successfully established TLS session with a certificate. Other investigated SSH, file-transfer and upload paths have convincing identity and timing continuity, so I have not extrapolated that defect into a claim that the whole collection is incoherent.

- **Detection Engineer:** Synthetic; verdict confidence 78; synthetic-confidence score 57. The collection is unusually strong on usable schemas and identity correlation: I found no demonstrated impossible process ordering or broken Zeek companion join in the checks performed. My synthetic verdict rests on a measurable Linux PID distribution artifact repeated across ten independent hosts, rather than attack progression, collection completeness, or missing out-of-window events. The score remains in the mixed band because this is a distribution finding, not a hard source-native contradiction.

- **Network Forensics Analyst:** Real; verdict confidence 68; synthetic-confidence score 24. The network evidence is mostly production-like: protocol records preserve connection identities, proxy traffic has coherent DNS/TCP/TLS and byte-accounting relationships, and an examined SSH session agrees with endpoint transport and authentication evidence. I found no demonstrated impossible network relationship; the principal reservation is an unusually absolute single-SYN pattern across unanswered TCP flows, including a small number attributed to ordinary application processes. This is a moderate-confidence authenticity judgment, not proof of provenance.

- **Host/EDR Forensics Analyst:** Inconclusive; verdict confidence 82; synthetic-confidence score 34. The endpoint collection is mostly production-like: Windows process identities agree across Security, Sysmon and eCAR, and representative Linux/macOS remote sessions preserve credible transport, authentication, shell and close relationships. A small amount of repetitive diagnostic activity and unusual shell-based access to binary documents raises a mild behavioral concern, but I did not establish a hard contradiction or a required cross-source companion gap; the records alone do not justify confidently assigning real or synthetic provenance.

## Deliberation Findings

Triggered by verdict disagreement and a52-point score spread. Facilitator rechecked the raw socket/TLS tuple and preserved all four original positions and scores;47.75 is the unchanged panel mean, not a re-vote.

## Prioritized Improvements

- **P0 — Raw Bash socket acquires established TLS.** Threat Hunter (original rating: not labeled), one exact callback, high leverage, low-to-medium adapter risk. Exact tuple and negotiated cipher/certificate evidence confirm a source-native protocol contradiction. Owner: typed pipeline submission semantics feeding canonical network construction.
- **P1 — Ground-truth timing verification double-counts observation delay.** Automated gate, repeated across 239 endpoint proofs, high acceptance leverage, low fix risk. Owner: evaluator timing-proof contract; source planner already recorded the final visible clock.
- **P2 — Shared Linux PID increment floor.** Detection (not labeled), 65/350 sysstat intervals exactly +940 across ten hosts, medium leverage, high allocator risk. Owner: temporal PID allocation/reorder capacity; qualify the floor before changing recovery-sensitive identities.
- **P3 — Single-SYN S0 observations and binary-document cat commands.** Network/Host (not labeled), weak signals with plausible scan/automation explanations; low leverage, no change selected.

## Priority Rationale

The exact process/protocol contradiction outranks weak distribution cues. The failed acceptance gate requires investigation independently of blind scores. No narrative-design or mere coverage/completeness observations are counted.

## Family Contract and Verification

Concentrated DB/perimeter activity was qualified against role/topology and shared baseline planner; no incompatible service selection was established. The next family contracts (final source timing proof and pipeline submission protocol intent) are documented in the worklog before coding. Raw Bash/TLS contradiction was independently rechecked by the deliberation facilitator.

## Comparison with Quantitative Eval

Automated evaluation: **91.0221/100 FAIL**, 148,961 records. Acceptance fails ground_truth.ground_truth_agreement at71.5965 (minimum95). The four earlier pillars remain above90; historical scores before this fifth pillar are not directly equivalent. Source integrity passed.

## Score Movement and Next Loop

Mean standalone synthetic-confidence47.75 versus67.00 in loop88. This combines fresh current-dev data with new independent sampling; do not attribute the change to a completed realism fix. Loop90 tests only the verifier repair on unchanged source data; pipeline protocol repair is targeted for loop91.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.
