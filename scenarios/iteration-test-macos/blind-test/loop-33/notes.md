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
