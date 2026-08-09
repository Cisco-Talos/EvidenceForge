# Iteration Test Expanded IDS Assessment Loops 35-44

Scenario: `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test-expanded-ids/scenario.yaml`

These loops begin from the integrated canonical-contract architecture. Loop 35
is a fresh baseline: no findings, scores, targets, or reports from loops 1-34
were used to select its improvements. Every loop regenerates data, runs the
deterministic evaluator, and gives only a neutral copy of the current data to
four independent blind reviewers.

## Pre-baseline Architecture Blocker

Fresh generation found a source-side SSH client whose outbound transport
outlived the inbound SSH session that owned the process. Source-process
attribution now requires the owning session to remain active through the full
transport; otherwise the canonical flow is retained without unsafe PID/user
attribution. Four focused tests passed, Ruff passed, and the full suite produced
5,289 passes plus 41 skips; its only sandbox failure was the localhost-port
Splunk harness test, which passed unrestricted.

## Loop 35 Outcome

- **Generation/eval:** 85,173 records; 95.91073999984621; automated FAIL only
  on pivot linkability (50/100). Canonical invariants, source schemas, field
  agreement, IDS integrity, and causal ordering all scored 100.
- **Blind panel:** Synthetic 3-1 at 64/64/28/66, average 55.5.
- **Deliberation:** Synthetic 3-1 at 68/69/44/71, average 63.0.
- **Fresh selected family:** version-specific source-native schema projection
  for Snort fast alerts, Security 4624 v2, and Sysmon Event 8 v2.
- **Owning abstraction:** emitter format definitions and source-native render
  adapters; canonical event truth remains unchanged.
- **Invariant:** rendered field labels, order, and presence match the declared
  native provider/version contract while preserving canonical values.
- **Sibling risks:** SIEM parsing, ordered XML fixtures, Snort classification
  semantics, Event 8 identity ownership, format validation, and deterministic
  output.
