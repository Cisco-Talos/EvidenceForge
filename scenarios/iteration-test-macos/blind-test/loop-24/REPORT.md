# Loop24 — certificate-ready TLS duration


Classification: family_level. Owner: shared canonical TLS transport timing and terminal-window bound. The close interval must contain actual sampled certificate observations plus finalization slack, without an unrelated chain-length-based 1.2-second floor. Entry paths: attach_ssl_context and final network accounting, including SSL, HTTPS/proxy, STARTTLS; consumers: all conn/files/x509 sensors, endpoint FLOW and terminal-window admission. Keep runtime-owned analyzer timing unchanged, with its overlay-safe upper bound. Verify several UIDs and a STARTTLS sibling, including long connections that must remain long. Remove only redundant chain-count floor and update its bound/test expectation; observation events must remain inside the transport.

## Verification

Revision420 removes the certificate-count-based1.2s minimum and derives the required close from sampled analyzer readiness plus slack.66 focused tests passed, including SSL and SMTP siblings, runtime close bounds and Zeek source tests; Ruff/format passed. Eval96.341564 PASS,133351 records,120 identical data files. Whole-output probe: zero observations in the former1.200070–1.201719s cluster (loop23DMZ122); all1241 checked TLS files across sensors fit the connection.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive; verdict confidence 78; synthetic-confidence score 43. The collection supports credible hunting pivots across endpoint, network, authentication, shell-history and proxy evidence. Repeated short-lived root desktop-indexer activity on infrastructure servers and repeated Windows management commands aimed at Linux hosts raise questions about baseline composition, but this bounded review found no demonstrated impossible lifecycle or decisive authenticity fingerprint. The score reflects those concrete, limited concerns rather than the completeness or narratability of the suspicious activity.

**Detection Engineer:** Synthetic; verdict confidence 73; synthetic-confidence score 62. The sampled Windows, Zeek, Linux and macOS records are largely processable and show substantial lifecycle and correlation care. I lean synthetic because embedded macOS file metadata has a strong fractional-timestamp distribution artifact across unrelated executables on both Macs; I found no demonstrated impossible lifecycle or broken network reference in the bounded checks, so this is a qualified verdict rather than certainty.

**Network Forensics:** Real; verdict confidence 68; synthetic-confidence score 18. The network records are production-like in the bounded checks performed: connection states, protocol timing, transfer accounting, DNS responses, and TLS certificate relationships remain internally coherent. I lean real, with moderate confidence because well-engineered synthetic telemetry could pass these checks and no packet capture or collection configuration is available to establish provenance.

**Host Forensics:** Inconclusive; verdict confidence 78; synthetic-confidence score 18. The bounded endpoint sample looks substantially production-like, with plausible process ancestry, varied session types, stable executable hashes, and coherent visible process lifetimes. I found no reproducible hard contradiction or strong synthetic distribution artifact; this supports a low synthetic-confidence score, but these checks cannot establish production provenance.

## Deliberation Findings

Standalone43/62/18/18 mean35.25; verdict confidence mean74.25. Disagreement triggered modeled facilitator revisions48/62/18/42 mean42.5. The lower-scoring bounded checks do not disprove Detection's stronger metadata census. These are not new reviewer turns or measured consensus.

## Prioritized Improvements

| Priority | Category | Scope/reviewer/leverage | Owner/action/risk |
|---|---|---|---|
| P1 | distribution_texture | Both Macs stat fractions; Detection; repeated/high | Canonical installed provisioning; loop25 distinguishes package-preserved build dates and full-range local filesystem time; moderate risk. |
| P1 | hard_contradiction, qualified | Prior loop23 shared TCP ceiling arithmetic; Network; high | Bounded loop24 Network did not check the same word-alignment invariant. Retain verified owner hypothesis and repair shared packet/IP ledger; moderate risk. |
| P2 | environment_or_collection_plausibility | Root tracker desktop indexer on web/app/monitor servers; Threat; repeated/medium | Role/installed-software-driven baseline process selection; verify and restrict catalog eligibility rather than emitter filtering; low/moderate risk. |
| P3 | weak_signal | Windows CIM commands target modeled Linux; Threat; repeated/low | World/planner target capability. Commands can fail so only reject generated successful Windows-management effects or inappropriate automatic default selection; low/moderate risk. |
| P4 | weak_signal | cifs-utils status probe; Host; low | No successful service operation established; do not patch based on unfamiliar command alone. |

## Quantitative comparison and rationale

The independent mean fell21 points from56.25. Direct probes establish that the targeted duration cluster disappeared, while the broad score change also reflects bounded-sample reviewer variation and different generated records. Quantitative score is stable above90. Metadata remains the first verified next target, followed by shared TCP accounting; qualified platform and service concerns require owner verification. Mac helper integer timings are explicitly authored scenario intent, confirmed in loop25 triage, and will not be randomized in the generator. No scenario edits or commits.
