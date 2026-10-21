# macOS mixed-fleet assessment

The agreed finite sequence is complete through revision 330 (`23e7e13e`): frozen
supported/native benchmark revisions, updated assessment reviewers, bounded native
fork integration, owner-level repairs, regression/recovery checks and a fresh
post-fix expert panel. Native ES exec/exit and Gatekeeper denial remain gated by
the user's October 21 decision. No capture is pending.

The final run passes deterministic acceptance at **89.2567**, **10,870 records**,
with 100% parseability and causality. The original lifecycle probe and selected
review-family probe have zero failures; the latter cleared 18 prior findings.
Three modeled fork/v10 rows are present. This is **not an authenticity pass**:
all four final reviewers judge Synthetic, with mean synthetic-confidence **66.75**.
A separate conservative check confirms two newly reported packet/history
contradictions in a pre-existing shared network loss routine.

## Assessment trend

Lower **synthetic-confidence scores** mean more production-like. Verdict
confidence is a separate measure and is never used as the loop score.

| Loop | Automated eval | Threat | Detection | Network | Host/EDR | Mean synthetic-confidence score | Interpretation | Deliberated score | Rolling mean, up to 5 loops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| [1](loop-1/REPORT.md) | 89.9919 FAIL | 82 | 82 | 84 | 84 | 83.00 | confidently synthetic | N/A | 83.00 (n=1) |
| [2](loop-2/REPORT.md) | 89.7644 PASS | 67 | 57 | 64 | 78 | 66.50 | likely synthetic | N/A | 74.75 (n=2) |
| [3](loop-3/REPORT.md) | 89.2567 PASS | 64 | 67 | 68 | 68 | 66.75 | likely synthetic | N/A | 72.08 (n=3) |

Loop 2's verdict disagreement triggered report-only deliberation; there were no
revised reviewer scores. Loop 3 is unanimous, average verdict confidence 82.5,
score spread four; no deliberation trigger fires. The final 0.25-point increase
is essentially flat: targeted defects cleared, while the panel exposed new
source semantics and timing issues. Standalone reviews do not prove the causal
score contribution of individual fixes.

[Assessment effectiveness dashboard](assessment-effectiveness-dashboard-last-3-loops.svg).

## What completed

- Separate immutable Schema 3 benchmark revisions and input/bundle/file provenance.
- Installed platform-aware personal assessment skill and all four reviewer personas;
  tracked patch plus retained original/replacement copies.
- Supported-source baseline and complete modeled SSH fork/v10 metadata through the
  ordinary CLI, parser, manifests, filtering and exact checkpoint recovery.
- Canonical lifecycle, netonly terminal placement, Linux SSH failure semantics,
  TLS accounting/history, CLI network ownership, GUI singleton reuse, journal
  machine identity, embedded history time, command-owned file effects, loaded
  browser version, physical HTTP timing and local actor-placement repairs.
- Catalog audit of all 67 original IDs, including five additional bounded runtime
  variants, for 48 prefilled Mac variants; unsupported entries remain unavailable.
- Forty relevant extended tests on final source. The complete routine run plus
  the repaired-fixture gate is recorded precisely in the worklog; no successful
  original full-suite exit is claimed. Ruff/format and 99 configuration checks pass.

## Remaining quality work

The [loop-3 synthesis](loop-3/REPORT.md) ranks all findings, preserves collection
qualifications, records owners and distinguishes verified contradictions from
leads. The highest priorities are:

| Priority | Finding | Status / owning layer |
| --- | --- | --- |
| P0 | Gap-marked TCP packet/history accounting | Two independently confirmed rows, 16 reported; shared network observation loss, unchanged since branch base. |
| P1 | Windows process births compressed to one readiness floor | Three independent reviewers, 14 processes; activity/readiness and source timing investigation. |
| P1–P2 | Native SMB service and NTP reference-ID semantics | Whole-family findings corroborated by primary references; protocol facts and source-native projection. |
| P2 | Mac local-query lifetime texture | Repeated 13–42 second utility lifetimes; command/activity duration policy. |
| P2–P4 | Service-owned HTTP, unmatched remote-auth tuples, Mac job-control defaults, module/retry texture | Qualified leads; confirm owner and collection contracts before changing output. |

These are explicit follow-up quality items, not hidden prerequisites to the
completed bounded implementation. General analyst-indistinguishability has not
been reached. Earlier TLS companion/closure partitioning remains an investigation
lead; valid IPv6 spelling alone remains unproven.

See [bounded acceptance](../ACCEPTANCE.md), the
[assessment worklog](../../../docs/worklog/2026-10-21-macos-assessment.md) and the
[capability matrix](../../../docs/design/macos-workstation-feasibility/capability-matrix.md)
for engineering scope and deferred evidence gates. No existing personal logs,
history, inventories or host services were inspected or changed.
