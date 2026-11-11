# Loop 90 — Authenticity assessment

Repaired final source-timing verification and reevaluated the unchanged authoritative bundle, followed by four fresh independent reviews. Generation data remain byte-identical to loop89.

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive; verdict confidence 78; synthetic-confidence score 28. The examined records are mostly production-like: exact-tuple SSH pivots, remote-credential semantics, and an outbound upload form technically workable investigations across independently rendered sources. A repeated browser-search referrer on domain-controller check-ins and an unusual runas parent are weak concerns, but neither establishes artificial origin or an impossible relationship. This is a bounded authenticity assessment, not an assertion that the visible suspicious activity is benign.

- **Detection Engineer:** Real; verdict confidence 65; synthetic-confidence score 18. The examined records are production-like from a detection engineering perspective: their native field shapes, numeric conventions, process identities, and independently joined network and authentication evidence are coherent. I did not establish a source-native contradiction or a score-bearing synthetic distribution artifact in this bounded review; the modest verdict confidence reflects that good synthetic telemetry could satisfy these same checks.

- **Network Forensics Analyst:** Real; verdict confidence 75; synthetic-confidence score 19. The network evidence is production-like, with coherent source-native connection states, diverse DNS outcomes, plausible TLS visibility, and working joins between network, proxy, certificate, and firewall records. I found no demonstrated hard contradiction or important synthetic indicator in this bounded investigation; the Real verdict is an assessment of the visible evidence, not proof of provenance.

- **Host/EDR Forensics Analyst:** Inconclusive; verdict confidence 80; synthetic-confidence score 42. The endpoint evidence is technically convincing across Windows, Linux and macOS, and this bounded investigation did not demonstrate an impossible process lifecycle or an exact-identity cross-source contradiction. Repeated Windows creator/target subject treatment and an unusual concentration of shell-based Office-document reads leave limited synthetic suspicion, but neither excludes real collection, impersonation, or automation. The score reflects mixed but predominantly production-like endpoint evidence, rather than certainty about the dataset's origin.

## Deliberation Findings

Triggered by Real/Inconclusive verdict disagreement. Facilitator retained all original scores;26.75 is the unchanged mean. Windows cross-user subjects remain ambiguous because impersonation can differ from process ownership.

## Prioritized Improvements

- **P0 — Raw Bash socket/TLS contradiction remains in this reviewed input.** Confirmed in loop89; this panel did not independently surface it. Owner: pipeline protocol-intent adapter, high leverage, low-to-medium risk. A later candidate generation is required to verify the fix.
- **P1 — Ground-truth acceptance still fails.** Automated report, multiple source-contract families, high acceptance leverage. Timing identity errors fell from239 to0; missing/factual/source-route and timing-dependency findings need exact qualification at the owning layer.
- **P2 — Windows Creator/Target subject semantics.** Host (original rating:not labeled),41 cross-user samples, medium potential leverage and medium risk. Parent owner does not prove effective creator token; retain as false_positive_or_unproven until invocation context establishes a contradiction.
- **P3 — Repeated referrer, binary-document cat and isolated runas parent.** Threat/Host (not labeled), weak texture, low leverage; no code change supported.

## Priority Rationale

The confirmed protocol contradiction remains above new qualified observations even when a fresh panel misses it. Timing correction repairs evaluator truth rather than making logs more production-like; blind movement cannot be its causal result.

## Family Contract and Verification

family_level evaluator repair. SourceTimingPlanner._record_finalized_process_dependent_time records final visible time after runtime observation/lifecycle constraints. verify_process_timing now compares it directly to expected_time. Four lifecycle phases with zero/nonzero delay and negative altered-clock/predecessor/order controls are tested;32 focused tests and full Ruff checks pass. No timing threshold or acceptance requirement changed.

## Comparison with Quantitative Eval

Automated evaluation: **94.3457/100 FAIL**, 148,961 records. Ground-truth agreement improved71.5965→88.2142; process_timing_identity_disagreement239→0. Minimum95 still fails. Other pillars and all148,961 source records are unchanged. This is a verifier correction, not a generated-data realism improvement.

## Score Movement and Next Loop

Standalone mean26.75, down21.00 from loop89 on byte-identical source data: reviewer/sampling variance. Deliberation preserved the original positions. Next loop verifies pipeline protocol repair; its initial generation exposed unmodeled-controller RDP reconnect admission, now under owner-level repair with focused controls.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.
