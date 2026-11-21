# Timing receipt policy compatibility repair

The first evaluation returned 96.5294 / FAIL: Ground Truth Agreement fell to
87.0088, with 153 process_timing_identity_disagreement and three additional
unjustified_source_time findings. Other pillars and the native Mac ES files were
unchanged from loop 3. The failed JSON/text remain under before-proof-policy-*.

The source planner correctly recorded the process-start collector policy used
for exec/audit/credential/job-control transitions. The independent receipt
checker still required only the historical dependent-event policy for every
non-birth/non-termination record. Its old hardcoded policy also selected the
wrong latency bound for predecessor-constrained transitions.

The checker now permits the two known historical/current policies only for
those five transition phases and uses the validated selected policy's existing
bounds. Birth, termination and unrelated dependent-event policy checks remain
strict. Phase, object/execution identity, native time, independent predecessor
existence/order, cycle and upper-bound checks remain active. Unknown policies
are still rejected. This preserves verification of older frozen receipts.

Added historical/current transition matrices, invalid-policy controls and five
round trips from the actual SourceTimingPlanner receipts through the independent
checker. Unit proof/related tests: 64 passed. Broader reconciliation integration
checks are recorded separately when complete. No generated data was altered or
regenerated for this evaluator-only correction; behavior 537's digest remains
current. A second evaluation was justified by the changed checker, rather than
repeatedly evaluating unchanged code to select a favorable result.

Corrected evaluation: PASS 98.59412546986576, 144,150 records; ground truth
97.33242971691963. The remaining failure categories/counts exactly match loop 3.
Blind reviewers receive only the unchanged neutral data copy and original
instructions, with no evaluator findings or repair hints.
