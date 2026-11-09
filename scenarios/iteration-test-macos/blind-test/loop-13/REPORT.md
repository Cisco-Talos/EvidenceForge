# Iterative assessment loop 13

## Outcome

Loop 13 repaired Linux storyline shell-history ownership in the storyline scheduler and typed
process handler. Optional shell-preparation commands now bind to the authored process's exact
interactive or SSH session, carry that logon ID into canonical event context, and cannot precede
source readiness. If the session is not ready or the remaining interval is too short, the optional
commands are skipped without moving the authored process. Behavior revision 412 records the
change.

The 96-test focused storyline suite passed. Repository Ruff lint/format checks and behavior-manifest
validation passed. Fresh output at `/private/tmp/eforge-iteration-test-macos-loop-13` produced
133,413 records and passed one JSON evaluation at 96.697351 (parseability 100.0, plausibility
96.7994, causality 95.9151, timing 92.5936). All 114 data files in the blind copy matched the
generated data directory byte-for-byte.

## Family probes

| Observation | Result |
|---|---|
| DB-PROD-01 root SSH accepted | 2026-11-02 18:15:23.014736 UTC |
| PAM session opened | 2026-11-02 18:15:23.078703 UTC |
| systemd session 279174 created | 2026-11-02 18:15:23.782296 UTC |
| First root history entry / authored process | 2026-11-02 18:15:26 UTC / 18:15:26.793 UTC |
| eCAR session logon ID | `0x1185fcb9` |
| Result | PASS — process follows session readiness; its eCAR context names the owning logon ID |

The remaining runway was too short for optional friction commands, so none were backfilled before
SSH authentication. Regression coverage also verifies that a ready local interactive session still
receives valid pre-process friction commands, and that insufficient post-auth runway suppresses
them. The authored process anchor remains unchanged.

## Independent expert panel

| Expert | Initial verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Inconclusive | 68 | 48 |
| Detection Engineer | Inconclusive | 72 | 56 |
| Network Forensics | Inconclusive | 58 | 25 |
| Host/EDR Forensics | Synthetic | 82 | 62 |
| **Mean** | **mixed/inconclusive** | **70.0** | **47.75** |

The verdict disagreement and 37-point score spread triggered deliberation. After cross-examination,
three experts remained inconclusive and Host/EDR remained synthetic; the final deliberation mean
synthetic-confidence was 49.0. The experts agreed that the records have strong investigative
correlation and no demonstrated hard contradiction. Repeated Mac timing texture remains the main
synthetic-facing family: reciprocal SSH command-to-authentication gaps near 19 seconds, clustered
process exits before logout on both hosts, and mirrored root-shell inventory-plist file operations.
The reports identify alternatives such as negotiation policy, application shutdown, and collector
serialization, so these are distribution-texture concerns rather than proven lifecycle violations.

## Prioritized findings

| Priority | Finding | Category | Reviewer original rating | Status |
|---|---|---|---|---|
| P1 | Linux shell-friction commands could appear before the root SSH session that owned the following authored process. | `contract_gap` | not labeled | Fixed and verified in loop 13 |
| P2 | Paired Macs show tightly clustered process exits immediately before their respective session logouts. | `distribution_texture` | not labeled | New candidate; inspect timing owner |
| P2 | Reciprocal Mac SSH sessions have nearly identical client-command-to-authentication intervals of about 19 seconds. | `distribution_texture` | not labeled | New candidate; verify source timing semantics |
| P3 | Mirrored root-shell create/delete operations affect the same inventory plist on both Macs on similar schedules. | `distribution_texture` | not labeled | New candidate; file actions do not prove launchd registration or activation |
| P4 | Linux shell histories reuse common diagnostic vocabulary; a few endpoint flows lack exact Zeek tuple matches. | `weak_signal` | not labeled | Low confidence; retain only with visible collection evidence |

## Comparison with quantitative evaluation

The evaluator accepted every hard criterion and scored 96.697351. It did not flag the repeated Mac
timing texture that shaped the expert panel's score range; conversely, expert review did not
identify an evaluator parseability, value, or causal-ordering failure. The score is 0.033 points
higher than loop 12, with 482 fewer records; this small movement is not treated as a material
quality drop.

## Next target

Prioritize the Mac process-termination timing family because both Detection and Host/EDR reviewers
identified it, it affects two independent hosts, and its visible sub-second cadence offers a
testable family-level invariant. Preserve process-before-session-close ordering while checking
whether planner slotting, source-timing repair, or collection delay creates the repeated cadence.
Treat the reciprocal SSH delay and mirrored plist operations as secondary candidates until their
canonical timing and action owners are traced. Keep the Linux history fix complete unless a fresh
probe finds a sibling session-owned history path with the same ordering defect.

Loop 13 is **complete**. The one evaluation, family contract and probes, four independent reports,
deliberation, and machine-readable scores are saved in this directory.
