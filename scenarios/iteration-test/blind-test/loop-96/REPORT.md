# Loop 96 — Authenticity assessment

Qualified the shared Linux PID increment fingerprint at its canonical allocator owner and ran a fresh four-expert panel on the fixed loop95 snapshot. No generator or scenario change in this checkpoint.

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 30. The bounded sample is mostly production-like: two independently selected suspicious activities support usable endpoint/network/application pivots with compatible identities, account ownership, and visible lifecycle ordering. I found no demonstrated contradiction or generator fingerprint in the 20 representative records examined; that supports a low synthetic-confidence score, but this small sample cannot establish production provenance.

- **Detection Engineer:** Real; verdict confidence 62; synthetic-confidence score 18. The bounded sample behaves like usable production telemetry: Windows field representations are source-appropriate, and two exact pivots preserve identity, tuple, and timing relationships. I found no demonstrated synthetic indicator; the Real verdict is tentative because a well-built synthetic collection could also pass these checks, and this review does not certify the full dataset.

- **Network Forensics Analyst:** Inconclusive; verdict confidence 78; synthetic-confidence score 30. The bounded network review found plausible connection states, protocol mixtures, DNS failures and certificate relationships, with two coherent exact-identity cross-source pivots. A small database-segment TLS population is unusually concentrated in legacy TLS 1.2 cipher choices, but this is readily explained by a fixed client configuration and does not establish synthetic origin. No demonstrated impossible relationship was found in the inspected records.

- **Host/EDR Forensics Analyst:** Inconclusive; verdict confidence 78; synthetic-confidence score 24. The bounded endpoint sample is predominantly production-like: Windows process identity agrees across three sources, and Linux SSH transport precedes authentication and session opening. I found no demonstrated impossible field value, exact-identity lifecycle inversion, or source-native contradiction; the available sample supports a low synthetic-confidence score, but does not establish production provenance.

## Deliberation Findings

Triggered by Real/Inconclusive disagreement. Original mean25.50 preserved; apparent escaping issue resolved. No new unconditional raw-log defect established.

## Prioritized Improvements

- **P1 — Ground-truth acceptance remains open.** Automated, repeated source-contract families, high correctness leverage. Current agreement88.3573<95; no acceptance pass inferred from strong blind reviews.
- **P2 — Shared temporal PID capacity floor.** Detection loop89 (original rating:not labeled), ten hosts/350 sysstat intervals with67 exactly+940, medium blind-score leverage and high allocator risk. Owner: StateManager hidden-churn prefix and30-second reorder lanes; minimum94 per minute is twice47-slot capacity.
- **P3 — Admin command pairs and small DB TLS population.** Host/Network (not labeled), weak distribution cues, low leverage. Decoded path strings exactly agree; escaping concern is a presentation false positive.

## Priority Rationale

The PID fingerprint is confirmed against both output and allocator mechanics, but changing its capacity model affects reservation ordering, uniqueness, PID wrap, scoped identities and exact recovery. An isolated jitter patch would violate the family contract. Retain a specific roadmap item and its acceptance controls rather than falsely presenting a local cosmetic fix.

## Family Contract and Verification

new_family diagnosis/deferred architecture. Invariant for a future family-level change: host workload should not collapse into a cross-host940-step mode, while every30-second lane retains bounded admission capacity and chronological/out-of-order recovery safety. Entry paths: baseline cron, SSH, storyline and scheduled/system process allocation; consumers: canonical process/session state, syslog/eCAR and checkpoint ownership. pid-floor-probe.json measures67/350 exact increments across ten hosts, and identifies the94/minute clamp. No code fix claimed. The existing source data are reused byte-identically with fresh blind isolation.

## Comparison with Quantitative Eval

Automated evaluation: **94.6124/100 FAIL**, 147,759 records. 94.6124 FAIL,147,759 records and ground-truth88.3573; identical to loop95. Final related tests255 and targeted slow1 pass; these do not close the quality gate.

## Score Movement and Next Loop

Mean25.50 versus24.75 in loop95 (+0.75), unchanged raw data: reviewer variance. Deliberation retained original scores. Loop97 will qualify remaining source-expectation failures and independently check the fixed snapshot.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.
