# Loop 52 Assessment Report

## Outcome

Loop 52 generated 82,371 records and scored 96.37. Fresh synthetic-confidence scores were
78 (Threat Hunter), 57 (Detection), 64 (Network), and 68 (Host/EDR), averaging 66.75. All four
reviewers returned Synthetic verdicts, confidence was adequate, and the score spread was 21,
so deliberation was not triggered.

## Fresh Expert Findings

- Threat Hunter found ordinary web clients allocated from operationally implausible public
  ranges, plus exact cron/DHCP schedules and PID 1 ownership of user tools.
- Detection found paraphrased Linux daemon messages, unstable sizes for immutable hashed assets,
  and bounded Kerberos/admin-command pools.
- Network found repeated 41.7–66.4 ms cross-sensor delays, exact packet-accounting identities,
  isolated proxy 407 failures, bounded DNS pools, and HTTP/1.1-only traffic.
- Host found fleet-wide admin/command pools, exact cron periodicity, repeated Windows command
  lines, and overly broad host access.

## Prioritized Improvements

1. **P0 — External-client allocation (`hard_plausibility`).** Ordinary web visitors can be
   drawn from globally assigned but operationally implausible DoD networks such as 29/8.
2. **P1 — Immutable asset identity (`hard_contradiction`).** Stable hashed asset paths must keep
   stable content sizes unless a deployment explicitly changes the asset.
3. **P2 — Source timing texture (`distribution_texture`).** Replace bounded cross-sensor offsets
   and exact periodic tasks with source and scheduler-specific models.
4. **P3 — Linux process ownership (`contract_gap`).** User-facing tools must not inherit PID 1
   merely because no modeled interactive owner is available.

## Implemented Fix

The canonical external-client allocator now consults a data-driven exclusion list for globally
assigned networks that are unsuitable as ordinary client populations. The list initially covers
DoD /8 allocations, including the observed 29/8 case, while retaining existing global-address,
special-use, and organization-CIDR checks. Focused external-IP and network-realism tests pass
(39 tests).

## Quantitative Comparison

Parseability was 100.0, plausibility 97.35, causality 90.71, and timing 96.77. The duplicate RDP
shell probe reached zero groups, confirming the Loop 51 state fix on freshly generated data.
