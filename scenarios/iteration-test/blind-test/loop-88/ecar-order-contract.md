# Loop 88 — eCAR Export Ordering Contract

## Question

Does strictly nondecreasing per-host eCAR timestamp order demonstrate an unsupported synthetic-only fingerprint?

## Probe

All 23 per-host eCAR files were parsed: 38,468 records and zero timestamp inversions. Millisecond ties occur in 13 files. The eCAR writer explicitly sets flat-file sorting and external sorting, defers sorted flush until close, and documents `_ecar_sort_key` as chronological per-host output sorting.

## Result

The observed ordering is an intentional chronological export contract. It does not assert source arrival order and is compatible with normalized telemetry exports. No generator defect is indicated; no code change selected.

## Verification

Counts are recorded in `ecar-order-probe.json`; the fresh Loop88 panel receives only the generated data directory and cannot see this probe or implementation details.
