# Loop 33: TCP history and zero payload

The shared canonical transport owner now removes data/retransmitted-data history when
that direction has explicitly zero payload, retaining unknown values and control/close
semantics. Zeek history collapses repeated observations; a history-only correction
preserves the already valid physical packet/ACK budget and does not advance its RNG.
No renderer-specific filtering was added.

Verification: 155 transport/TLS/proxy tests, two SF/reset syslog integration cases and
33 transport tests including the new RNG/physical-budget stability case pass (overlap
between suites). Ruff and formatting passed. The full validation/generation/eval retry
passed: 96.0691, 135636 records, 117 files. Rendered clean TCP data/zero contradictions
are zero. Remaining clean-to-partial sensor header-delta failures are 286, targeted in34.

An initial packet-recounting attempt exposed a separate external-source RDP reconnect
failure. The exact path excludes an unmodeled source (10.10.1.99); compatibility then
rekeys an established RDP session while processes retain its prior ID. Two instrumented
CLI reproductions retained validation and captured exact identity/eligibility evidence;
failed console and behavior snapshots are retained. This needs an authenticated,
allocation-free existing-session reconnect contract, not a fabricated source process,
renderer rewrite, or relaxed lifecycle assertion. It is a high-priority family for35.

The first attempt was not assessed. Accepted data comes from revision430 and the clean
retry bundle; byte-identical neutral data/provenance are retained. The scenario and
historical scores were preserved. This loop changes native history semantics; it does
not certify unrelated RDP compatibility or sequence-derived Zeek byte semantics.

Next priorities: P0 packet/header capture partition (Network32, repeated, high impact,
observation owner, medium risk); P0 external RDP reconnect (reproduced runtime failure,
exact State/RDP owner, medium/high risk); P1 SSH phase packet budgets and browser build
identity; P2 baseline SMB cadence. Original reviewer priority labels were not assigned.

Quantitative audit correction in42: overall96.0691was high, but the hard pivot-
linkability gate was79.8942below80 (151/189inferred edges); raw acceptance_passed
was false. Earlier PASS labels based only on overall score were wrong. Canonical
status is now REVIEW, without changing numbers, blind reports or scores. Examples
include inferred cross-track Web/Linux→Mac narrative links; these are heuristic
pivot shortfalls, not evidence of a new protocol impossibility. By35the metric was
161/189=85.1852and all hard gates passed;35–41remainpassing. No threshold or scenario
was changed to obtain that result.


## Family contract

# Final TCP payload/history reconciliation

Classification: sibling_defect; family_level. Owner: shared canonical TCP transport planning, after final payload/physical accounting and before source observation. Explicit zero directional payload cannot retain observed data/retransmitted-data history. Preserve unknown payload and control/close history; do not invent bytes to satisfy a template. Existing absence-of-data-marker payload shaping remains intact. Entry paths: generic baseline/storyline connections, explicit transport states, protocol shaping, and later canonical payload reconciliation. Consumers: Zeek, eCAR, firewall and application transport ledgers. Both planner and draft alignment use one helper; source-observation loss is separate work for34. Cover successful/reset, both directions, retransmission and unknown values. Medium risk from dependent randomized packet shapes; check proxy/lifecycle contracts.

History is a collapsed native summary, not an exhaustive packet list. A history-only correction preserves the valid physical ACK/options budget and independent RNG choices; payload changes still recompute dependent ledgers. Separate external-source RDP reconnect re-keying was exposed by an initial counter-changing attempt and is retained as a high-risk architectural finding, with assertions intact.


## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 76; synthetic-confidence score 36. The collection is operationally credible: web execution, SSH transport and authentication, database staging, SMB transfers, and a proxy-mediated upload support usable investigative pivots. I found weak signs of reusable administrative activity templates, but no demonstrated impossible lifecycle or attack-effect contradiction in the checks performed. The evidence supports a mostly realistic collection while remaining insufficient to establish its provenance.

**Detection Engineer:** Synthetic; verdict confidence 80; synthetic-confidence score 64. The records are technically convincing and would largely support ordinary SIEM parsing and correlation. My synthetic verdict rests on a concrete, fleet-wide distribution fingerprint in Linux service noise: precisely eight D-Bus messages on every one of eleven hosts, and precisely three or six polkit messages according to host class, with a pronounced early-window concentration on servers. I found no demonstrated impossible process lifecycle, broken Zeek connection reference, or native macOS authorization/notification contradiction; those successful checks materially limit the score.

**Network Forensics:** Real; verdict confidence 66; synthetic-confidence score 31. The network records are mostly production-like: protocol metadata, TCP state, byte accounting, certificate identities, and overlapping sensor observations remain coherent under cross-checks. I lean Real, with modest confidence because an unusually small-gap-heavy capture-loss distribution is a possible modeling artifact, although it is not a demonstrated contradiction.

**Host Forensics:** Synthetic; verdict confidence 82; synthetic-confidence score 67. The endpoint evidence is mostly convincing at the identity, process-tree and correlation levels, but repeated exact-duration macOS activity and fixed Linux background-message quotas suggest synthetic construction. This verdict rests on measurable distribution artifacts, not a demonstrated impossible process lifecycle or on the apparent completeness of the suspicious activity.


## Scores and comparison

Automated eval 96.0691; standalone synthetic-confidence average 49.50 (mixed/inconclusive), prior loop 67.75. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 64.00; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.

## Quantitative acceptance

REVIEW: high overall score does not override failed hard criteria. 
- causality.pivot_linkability: 79.8942 < 80.0000.
